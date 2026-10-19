//! The store behind the logbook: the newest entries in memory, every write
//! committed to an SQLite database by a writer thread.

use super::{
    kind, rfc3339, to_millis, Entry, Event, Level, Options, Page, Query, Stop, COALESCE_WINDOW,
    DEFAULT_LIMIT, MAX_LIMIT, RETENTION,
};
use parking_lot::Mutex;
use rusqlite::types::Value as SqlValue;
use rusqlite::{
    params, params_from_iter, Connection, ErrorCode, OpenFlags, Row, TransactionBehavior,
};
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::collections::{btree_map, BTreeMap, HashMap, VecDeque};
use std::fmt::Write as _;
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender, TrySendError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tracing::warn;

const DB_FILE: &str = "logbook.db";
/// An unreadable database is moved here and the logbook starts over.
const CORRUPT_FILE: &str = "logbook.db.corrupt";
const LOCK_FILE: &str = "logbook.lock";
/// Present while a run is going; left behind by a run that never stopped.
const RUN_MARKER: &str = "run.json";

/// `PRAGMA user_version` of [`SCHEMA`]. A database from a newer meow is
/// left alone, neither read nor rewritten.
const SCHEMA_VERSION: i64 = 1;

/// A contract with readers in other processes (ADR-0014). Times are Unix
/// milliseconds, `last` is `time` until a repeat folds in, `subject` is
/// empty when the event has none, and `fields` is a JSON object or NULL.
/// AUTOINCREMENT keeps ids increasing past deleted rows.
const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS entries (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    rev     INTEGER NOT NULL,
    time    INTEGER NOT NULL,
    last    INTEGER NOT NULL,
    count   INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    level   TEXT NOT NULL,
    subject TEXT NOT NULL,
    message TEXT NOT NULL,
    fields  TEXT
);
CREATE INDEX IF NOT EXISTS entries_rev ON entries (rev);
";

/// The writer's connection: commits survive a killed process, and a power
/// cut can lose the last ones but not the database (WAL with `synchronous`
/// NORMAL). The write-ahead log is checkpointed every 64 pages and cut
/// back to 256 KiB, and the page cache is 256 KiB, for the memory limit of
/// an iOS network extension.
const TUNING: &str = "
PRAGMA synchronous = NORMAL;
PRAGMA wal_autocheckpoint = 64;
PRAGMA journal_size_limit = 262144;
PRAGMA cache_size = -256;
";

const UPSERT: &str = "
INSERT INTO entries (id, rev, time, last, count, kind, level, subject, message, fields)
VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)
ON CONFLICT (id) DO UPDATE SET
    rev = excluded.rev,
    last = excluded.last,
    count = excluded.count,
    message = excluded.message,
    fields = excluded.fields
WHERE excluded.rev > entries.rev
";

/// Writes waiting for the writer thread. Past this, recording keeps a
/// write pending in memory rather than wait on the disk. Also the most
/// writes a failed commit keeps for a retry.
const QUEUE: usize = 1024;

/// Most operations committed in one transaction.
const BATCH: usize = 256;

/// How long [`Logbook::flush`] and a read of the database wait for the
/// writer.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

/// How long a connection waits for a lock held by another.
const BUSY_TIMEOUT: Duration = Duration::from_secs(1);

/// Expired entries are deleted at open, then at most this often.
const PRUNE_INTERVAL: Duration = Duration::from_secs(60 * 60);

/// A commit that failed is tried again after this, or with the next one.
const RETRY_INTERVAL: Duration = Duration::from_secs(10);

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A repeat folded into an entry reaches the disk at most this often, and
/// at the latest this long after it happened. The entry in memory is
/// always current; a crash loses at most this much of its count.
const FOLD_WRITE_INTERVAL: Duration = Duration::from_secs(60);

/// A logbook in one directory, reached through [`super::current`]; see the
/// [module docs](super).
pub struct Logbook {
    dir: PathBuf,
    options: Options,
    /// Shared with the writer, which writes out held-back repeats once due.
    state: Arc<Mutex<State>>,
    /// Entries below this `id` were cleared: the writer deletes them, and
    /// drops their writes still queued.
    cleared: Arc<AtomicU64>,
    writer: Option<JoinHandle<()>>,
    /// Held for the logbook's lifetime; the OS releases it with the file.
    _lock: File,
}

struct State {
    next_id: u64,
    rev: u64,
    /// The newest entries, by ascending `id`.
    recent: VecDeque<Slot>,
    /// The highest `rev` among entries kept only on disk; 0 when none.
    disk_rev: u64,
    /// The latest entry of each kind and subject, for coalescing.
    latest_by_subject: HashMap<(SmolStr, SmolStr), u64>,
    /// Latest occurrence of any entry.
    last_seen: Option<SystemTime>,
    run_started: Option<SystemTime>,
    /// When the earliest held-back repeat is due; `None` when none is.
    held_due: Option<SystemTime>,
    queue: Queue,
}

struct Slot {
    entry: Entry,
    /// When the entry was last queued for the disk.
    written: SystemTime,
    /// A folded repeat is not queued yet (see [`FOLD_WRITE_INTERVAL`]).
    dirty: bool,
}

/// The writer thread's queue, used under the state lock: an entry's writes
/// reach the database in `rev` order.
struct Queue {
    /// `None` once the logbook closes, which stops the writer.
    tx: Option<SyncSender<Op>>,
    /// Warned that the writer fell behind.
    warned: bool,
}

enum Op {
    /// Insert the entry, or bring its row up to this write.
    Write(Box<Entry>),
    /// A repeat was held back: look for when it is due.
    Wake,
    Select(Box<Select>),
    Flush(SyncSender<()>),
}

/// A read of the entries that left memory.
struct Select {
    query: Query,
    horizon: SystemTime,
    /// Entries with a lower `id`: the ones in memory are not read again.
    below: Option<u64>,
    limit: usize,
    reply: SyncSender<io::Result<Vec<Entry>>>,
}

impl Query {
    fn page_size(&self) -> usize {
        self.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT)
    }

    fn matches(&self, entry: &Entry) -> bool {
        self.before.is_none_or(|before| entry.id < before)
            && self.since.is_none_or(|since| entry.rev > since)
            && self.level.is_none_or(|level| entry.level >= level)
            && self.kind.as_deref().is_none_or(|kind| {
                entry.kind == kind
                    || entry
                        .kind
                        .strip_prefix(kind)
                        .is_some_and(|rest| rest.starts_with('.'))
            })
            && self
                .subject
                .as_deref()
                .is_none_or(|subject| entry.subject == subject)
    }
}

#[derive(Serialize, Deserialize)]
struct RunMarker {
    #[serde(with = "rfc3339")]
    started: SystemTime,
    version: String,
}

impl Logbook {
    /// Open the logbook in `dir`, creating it if needed. Fails when another
    /// process holds it, or when a newer meow wrote its database.
    pub fn open(dir: &Path, options: Options) -> io::Result<Self> {
        Self::open_at(dir, options, SystemTime::now())
    }

    pub(super) fn open_at(dir: &Path, options: Options, now: SystemTime) -> io::Result<Self> {
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
        let horizon = horizon(now, options.retention);
        let (conn, loaded, reset) = match open_db(&path, &options, horizon) {
            Ok((conn, loaded)) => (conn, loaded, None),
            Err(Unusable::Damaged(error)) => {
                warn!(
                    "logbook: cannot read {} ({error}); starting over and keeping it as {CORRUPT_FILE}",
                    path.display()
                );
                set_aside(dir)?;
                let (conn, loaded) =
                    open_db(&path, &options, horizon).map_err(Unusable::into_io)?;
                (conn, loaded, Some(error))
            }
            Err(Unusable::Failed(e)) => return Err(e),
        };
        let recent: VecDeque<Slot> = loaded
            .recent
            .into_iter()
            .map(|entry| Slot {
                written: entry.last_time(),
                entry,
                dirty: false,
            })
            .collect();
        // Ascending ids, so each subject ends up at its latest entry.
        let latest_by_subject = recent
            .iter()
            .map(|slot| {
                let entry = &slot.entry;
                ((entry.kind.clone(), entry.subject.clone()), entry.id)
            })
            .collect();

        let (tx, rx) = mpsc::sync_channel(QUEUE);
        let state = Arc::new(Mutex::new(State {
            next_id: loaded.next_id,
            rev: loaded.rev,
            recent,
            disk_rev: loaded.disk_rev,
            latest_by_subject,
            last_seen: loaded.last_seen,
            run_started: None,
            held_due: None,
            queue: Queue {
                tx: Some(tx),
                warned: false,
            },
        }));
        let cleared = Arc::new(AtomicU64::new(0));
        let writer = Writer {
            conn,
            path,
            max_size: options.max_size,
            retention: options.retention,
            pruned: now,
            state: Arc::clone(&state),
            cleared: Arc::clone(&cleared),
            deleted_below: 0,
            backlog: BTreeMap::new(),
            retry_at: None,
            failing: false,
            upkeep_failing: false,
        };
        let thread = std::thread::Builder::new()
            .name("meow-logbook".into())
            .spawn(move || writer.run(&rx))?;

        let book = Self {
            dir: dir.to_owned(),
            options,
            state,
            cleared,
            writer: Some(thread),
            _lock: lock,
        };
        if let Some(error) = reset {
            book.record_at(
                super::event(
                    kind::LOGBOOK_RESET,
                    Level::Warning,
                    format!(
                        "The logbook could not be read and started over; the old database is kept as {CORRUPT_FILE}"
                    ),
                )
                .field("error", error),
                now,
            );
        }
        Ok(book)
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record(&self, event: Event) {
        self.record_at(event, SystemTime::now());
    }

    pub(super) fn record_at(&self, event: Event, now: SystemTime) -> Entry {
        self.state
            .lock()
            .write(event, to_millis(now), &self.options)
    }

    /// Entries matching `query`, newest first. Paging back past the
    /// entries kept in memory reads the database, so call it off the async
    /// runtime; it fails when the database cannot answer.
    pub fn query(&self, query: &Query) -> io::Result<Page> {
        self.query_at(query, SystemTime::now())
    }

    pub(super) fn query_at(&self, query: &Query, now: SystemTime) -> io::Result<Page> {
        let limit = query.page_size();
        let horizon = horizon(now, self.options.retention);
        let (rev, mut entries, past_memory) = {
            let state = self.state.lock();
            let entries: Vec<Entry> = state
                .recent
                .iter()
                .rev()
                .map(|slot| &slot.entry)
                .filter(|entry| entry.last_time() >= horizon && query.matches(entry))
                .take(limit + 1)
                .cloned()
                .collect();
            // The entries in memory are current; the database is needed
            // only for the ones that left it, and a poll only when one of
            // those changed since.
            let past_memory = (entries.len() <= limit && query.since.unwrap_or(0) < state.disk_rev)
                .then(|| {
                    (
                        state.recent.front().map(|slot| slot.entry.id),
                        state.queue.tx.clone(),
                    )
                });
            (state.rev, entries, past_memory)
        };
        if let Some((below, tx)) = past_memory {
            let tx = tx.ok_or_else(|| io::Error::other("the logbook is closed"))?;
            let room = limit + 1 - entries.len();
            entries.extend(read_queued(&tx, query, horizon, below, room)?);
        }
        let more = entries.len() > limit;
        entries.truncate(limit);
        Ok(Page { entries, rev, more })
    }

    /// Delete every entry, then record that the logbook was cleared, and
    /// wait (briefly) for the writer. Ids keep increasing, so a client drops
    /// whatever it holds below the `logbook.cleared` entry.
    pub fn clear(&self) {
        let tx = {
            let mut state = self.state.lock();
            state.recent.clear();
            state.latest_by_subject.clear();
            state.disk_rev = 0;
            state.held_due = None;
            // Never waits on the writer: it reads the bound before each
            // commit, so a clear is neither dropped nor stuck behind a full
            // queue.
            self.cleared.store(state.next_id, Ordering::Release);
            state.write(
                super::event(kind::LOGBOOK_CLEARED, Level::Info, "Cleared the logbook"),
                to_millis(SystemTime::now()),
                &self.options,
            );
            state.queue.tx.clone()
        };
        if let Some(tx) = tx {
            flush_queued(&tx);
        }
    }

    /// Write out pending repeats and wait (briefly) for the writer.
    pub fn flush(&self) {
        let tx = {
            let mut state = self.state.lock();
            state.write_held(SystemTime::now(), true);
            state.queue.tx.clone()
        };
        if let Some(tx) = tx {
            flush_queued(&tx);
        }
    }

    /// Wait for the writer without writing out pending repeats.
    #[cfg(test)]
    pub(super) fn settle(&self) {
        let tx = self.state.lock().queue.tx.clone();
        if let Some(tx) = tx {
            flush_queued(&tx);
        }
    }

    /// The level of the latest entry of `kind` for `subject`, while that
    /// entry is among the ones kept in memory and not expired.
    pub fn latest_level(&self, kind: &str, subject: &str) -> Option<Level> {
        self.latest_level_at(kind, subject, SystemTime::now())
    }

    pub(super) fn latest_level_at(
        &self,
        kind: &str,
        subject: &str,
        now: SystemTime,
    ) -> Option<Level> {
        let state = self.state.lock();
        let id = *state
            .latest_by_subject
            .get(&(SmolStr::new(kind), SmolStr::new(subject)))?;
        let i = state
            .recent
            .binary_search_by_key(&id, |slot| slot.entry.id)
            .ok()?;
        let entry = &state.recent[i].entry;
        (entry.last_time() >= horizon(now, self.options.retention)).then_some(entry.level)
    }

    /// Watch the run that started at `started`: report an unclean exit if
    /// the previous run's marker is still there, and leave a marker for
    /// this one.
    pub(super) fn track_run(&self, started: SystemTime, now: SystemTime) {
        let now = to_millis(now);
        let marker = self.dir.join(RUN_MARKER);
        let previous = fs::read(&marker)
            .ok()
            .and_then(|bytes| serde_json::from_slice::<RunMarker>(&bytes).ok());
        if let Some(previous) = previous {
            let since = rfc3339::format(previous.started);
            let mut event = super::event(
                kind::ENGINE_UNCLEAN_EXIT,
                Level::Warning,
                format!(
                    "The previous run (meow {}, started {since}) ended without a clean stop",
                    previous.version
                ),
            )
            .field("version", previous.version)
            .field("started", since);
            let last_seen = self.state.lock().last_seen;
            if let Some(last_seen) = last_seen.filter(|seen| *seen >= previous.started) {
                event = event.field("lastSeen", rfc3339::format(last_seen));
            }
            self.record_at(event, now);
        }
        let run = RunMarker {
            started: to_millis(started),
            version: VERSION.to_owned(),
        };
        if let Err(e) = serde_json::to_vec(&run)
            .map_err(io::Error::from)
            .and_then(|bytes| fs::write(&marker, bytes))
        {
            warn!("logbook: cannot write {}: {e}", marker.display());
        }
        self.state.lock().run_started = Some(run.started);
    }

    /// Stop watching the run. A run that stops recording cannot tell a
    /// crash from a clean stop, so it leaves no marker behind.
    pub(super) fn untrack_run(&self) {
        self.state.lock().run_started = None;
        remove(&self.dir.join(RUN_MARKER));
    }

    pub(super) fn engine_started(&self, config: &str, now: SystemTime) {
        self.track_run(now, now);
        self.record_at(
            super::event(
                kind::ENGINE_START,
                Level::Info,
                format!("Started meow {VERSION}"),
            )
            .field("version", VERSION)
            .field("config", config),
            now,
        );
    }

    pub(super) fn engine_stopped(&self, stop: Stop<'_>, now: SystemTime) {
        let now = to_millis(now);
        let started = self.state.lock().run_started;
        let uptime = started.and_then(|started| now.duration_since(started).ok());
        let stopped = match uptime {
            Some(uptime) => format!("Stopped after {}", format_uptime(uptime)),
            None => String::from("Stopped"),
        };
        let mut event = match stop {
            Stop::Requested(by) => {
                super::event(kind::ENGINE_STOP, Level::Info, format!("{stopped} ({by})"))
                    .field("reason", by)
            }
            Stop::Failed(error) => super::event(
                kind::ENGINE_STOP,
                Level::Error,
                format!("{stopped}: {error}"),
            )
            .field("error", error),
        };
        if let Some(uptime) = uptime {
            event = event.field("uptime", uptime.as_secs());
        }
        self.record_at(event, now);
        self.untrack_run();
        self.flush();
    }
}

impl Drop for Logbook {
    fn drop(&mut self) {
        {
            let mut state = self.state.lock();
            state.write_held(SystemTime::now(), true);
            // Closing the queue lets the writer finish what is queued and
            // exit.
            state.queue.tx = None;
        }
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

impl Queue {
    /// Queue `op` without waiting: false when the writer is behind, or
    /// gone.
    fn send(&mut self, op: Op) -> bool {
        let Some(tx) = &self.tx else {
            return false;
        };
        match tx.try_send(op) {
            Ok(()) => true,
            Err(TrySendError::Full(_)) => {
                if !self.warned {
                    warn!("logbook: the writer fell behind; writes are delayed and may be lost");
                    self.warned = true;
                }
                false
            }
            Err(TrySendError::Disconnected(_)) => false,
        }
    }

    /// Wake the writer to look for held-back repeats. A full queue keeps
    /// it awake anyway.
    fn wake(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.try_send(Op::Wake);
        }
    }
}

/// Queue `op` behind everything queued, waiting until `deadline` for room.
fn send_by(tx: &SyncSender<Op>, mut op: Op, deadline: Instant) -> bool {
    loop {
        match tx.try_send(op) {
            Ok(()) => return true,
            Err(TrySendError::Full(back)) if Instant::now() < deadline => {
                op = back;
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(_) => return false,
        }
    }
}

/// Wait (briefly) until the writer has committed everything queued.
fn flush_queued(tx: &SyncSender<Op>) {
    let deadline = Instant::now() + FLUSH_TIMEOUT;
    let (ack, done) = mpsc::sync_channel(1);
    if send_by(tx, Op::Flush(ack), deadline) {
        let _ = done.recv_timeout(deadline.saturating_duration_since(Instant::now()));
    }
}

/// Read the database after everything queued.
fn read_queued(
    tx: &SyncSender<Op>,
    query: &Query,
    horizon: SystemTime,
    below: Option<u64>,
    limit: usize,
) -> io::Result<Vec<Entry>> {
    let deadline = Instant::now() + FLUSH_TIMEOUT;
    let (reply, entries) = mpsc::sync_channel(1);
    let select = Select {
        query: query.clone(),
        horizon,
        below,
        limit,
        reply,
    };
    let unanswered = || io::Error::new(io::ErrorKind::TimedOut, "the logbook writer is behind");
    if !send_by(tx, Op::Select(Box::new(select)), deadline) {
        return Err(unanswered());
    }
    entries
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| unanswered())?
}

impl State {
    /// The next revision. Never below the clock, so revs keep increasing
    /// across a restart even past writes a crash lost.
    fn next_rev(&mut self, now: SystemTime) -> u64 {
        self.rev = (self.rev + 1).max(millis(now));
        self.rev
    }

    fn write(&mut self, event: Event, now: SystemTime, options: &Options) -> Entry {
        self.last_seen = Some(now);
        if event.coalesce {
            if let Some(i) = self.fold_target(&event, now) {
                let rev = self.next_rev(now);
                let slot = &mut self.recent[i];
                let entry = &mut slot.entry;
                entry.rev = rev;
                entry.count = entry.count.saturating_add(1);
                entry.last = Some(now);
                entry.message = event.message;
                entry.fields = event.fields;
                slot.dirty = true;
                if is_due(slot.written, now) {
                    self.send_slot(i, now);
                } else {
                    self.hold(i);
                }
                return self.recent[i].entry.clone();
            }
        }
        // Make room first, so that a held-back repeat written out as its
        // entry leaves takes a lower rev than the new entry.
        while self.recent.len() >= options.recent.max(1) {
            let Some(mut evicted) = self.recent.pop_front() else {
                break;
            };
            if evicted.dirty {
                // A new revision, as in `write_out`.
                evicted.entry.rev = self.next_rev(now);
                self.disk_rev = self.disk_rev.max(evicted.entry.rev);
                self.queue.send(Op::Write(Box::new(evicted.entry)));
            } else {
                self.disk_rev = self.disk_rev.max(evicted.entry.rev);
            }
        }
        let entry = Entry {
            id: self.next_id,
            rev: self.next_rev(now),
            time: now,
            last: None,
            count: 1,
            kind: SmolStr::new_static(event.kind),
            level: event.level,
            subject: event.subject,
            message: event.message,
            fields: event.fields,
        };
        self.next_id += 1;
        let queued = self.queue.send(Op::Write(Box::new(entry.clone())));
        self.latest_by_subject
            .insert((entry.kind.clone(), entry.subject.clone()), entry.id);
        self.recent.push_back(Slot {
            entry: entry.clone(),
            written: now,
            dirty: !queued,
        });
        if !queued {
            // Pending like a held-back repeat, for the writer to retry.
            self.hold(self.recent.len() - 1);
        }
        if self.latest_by_subject.len() > 4 * options.recent {
            let oldest = self.recent.front().map_or(0, |slot| slot.entry.id);
            self.latest_by_subject.retain(|_, id| *id >= oldest);
        }
        entry
    }

    /// Queue slot `i`. When the writer is behind, it stays held back for
    /// the writer to retry.
    fn send_slot(&mut self, i: usize, now: SystemTime) {
        let entry = Box::new(self.recent[i].entry.clone());
        if self.queue.send(Op::Write(entry)) {
            let slot = &mut self.recent[i];
            slot.dirty = false;
            slot.written = now;
        } else {
            self.hold(i);
        }
    }

    /// Note that slot `i` holds a repeat not written yet, and wake the
    /// writer for it.
    fn hold(&mut self, i: usize) {
        if self.held_due.is_none() {
            self.queue.wake();
        }
        self.note_held(i);
    }

    fn note_held(&mut self, i: usize) {
        let due = fold_due(self.recent[i].written);
        self.held_due = Some(self.held_due.map_or(due, |held| held.min(due)));
    }

    /// Queue slot `i`'s held-back repeat as a new revision: a reader that
    /// polled past its fold, at a later entry's rev, still sees it.
    fn write_out(&mut self, i: usize, now: SystemTime) {
        self.recent[i].entry.rev = self.next_rev(now);
        self.send_slot(i, now);
    }

    /// Queue the held-back repeats due at `now`, or all of them.
    fn write_held(&mut self, now: SystemTime, all: bool) {
        self.held_due = None;
        for i in 0..self.recent.len() {
            let slot = &self.recent[i];
            if !slot.dirty {
                continue;
            }
            if all || is_due(slot.written, now) {
                self.write_out(i, now);
            } else {
                self.note_held(i);
            }
        }
    }

    /// The entry `event` folds into, if any (see [`Event::coalesce`]).
    fn fold_target(&self, event: &Event, now: SystemTime) -> Option<usize> {
        let key = (SmolStr::new_static(event.kind), event.subject.clone());
        let id = *self.latest_by_subject.get(&key)?;
        let i = self
            .recent
            .binary_search_by_key(&id, |slot| slot.entry.id)
            .ok()?;
        let entry = &self.recent[i].entry;
        let age = now.duration_since(entry.last_time()).unwrap_or_default();
        (entry.level == event.level && age <= COALESCE_WINDOW).then_some(i)
    }
}

/// Whether a repeat of an entry last queued at `written` is due at `now`.
fn is_due(written: SystemTime, now: SystemTime) -> bool {
    !now.duration_since(written)
        .is_ok_and(|since| since < FOLD_WRITE_INTERVAL)
}

fn fold_due(written: SystemTime) -> SystemTime {
    written.checked_add(FOLD_WRITE_INTERVAL).unwrap_or(written)
}

/// Why the database could not be opened.
enum Unusable {
    /// Not a database, a damaged one, or rows meow cannot read: set it
    /// aside and start over.
    Damaged(String),
    Failed(io::Error),
}

impl From<rusqlite::Error> for Unusable {
    fn from(e: rusqlite::Error) -> Self {
        let damaged = matches!(
            e.sqlite_error_code(),
            Some(ErrorCode::DatabaseCorrupt | ErrorCode::NotADatabase)
        ) || matches!(
            e,
            rusqlite::Error::FromSqlConversionFailure(..)
                | rusqlite::Error::InvalidColumnType(..)
                | rusqlite::Error::IntegralValueOutOfRange(..)
                | rusqlite::Error::Utf8Error(..)
        );
        if damaged {
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

/// Connect, delete what expired or is over the cap, and load the newest
/// entries.
fn open_db(
    path: &Path,
    options: &Options,
    horizon: SystemTime,
) -> Result<(Connection, Loaded), Unusable> {
    let conn = connect(path)?;
    for result in [prune(&conn, horizon), cap(&conn, options.max_size)] {
        if let Err(e) = result {
            warn!("logbook: cannot maintain {}: {e}", path.display());
        }
    }
    let loaded = load(&conn, options.recent, horizon)?;
    Ok((conn, loaded))
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
    // Readers in other processes never block the writer, nor it them. A
    // file system without shared memory keeps the rollback journal.
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
        remove(&dir.join(format!("{DB_FILE}{suffix}")));
    }
    Ok(())
}

/// What the database holds at open.
struct Loaded {
    /// The newest unexpired entries, by ascending `id`.
    recent: Vec<Entry>,
    next_id: u64,
    rev: u64,
    /// The highest `rev` among the unexpired entries not in `recent`.
    disk_rev: u64,
    last_seen: Option<SystemTime>,
}

fn load(conn: &Connection, recent: usize, horizon: SystemTime) -> rusqlite::Result<Loaded> {
    let mut newest = select(conn, &Query::default(), horizon, None, recent)?;
    newest.reverse();
    // AUTOINCREMENT keeps the highest id ever used, deleted or not.
    let max_id: u64 = conn.query_row(
        "SELECT COALESCE(MAX(seq), 0) FROM sqlite_sequence WHERE name = 'entries'",
        [],
        |row| row.get(0),
    )?;
    let (rev, last_seen): (Option<u64>, Option<u64>) =
        conn.query_row("SELECT MAX(rev), MAX(last) FROM entries", [], |row| {
            Ok((row.get(0)?, row.get(1)?))
        })?;
    let disk_rev: Option<u64> = match newest.first() {
        Some(oldest) => conn.query_row(
            "SELECT MAX(rev) FROM entries WHERE id < ?1 AND last >= ?2",
            params![oldest.id, millis(horizon)],
            |row| row.get(0),
        )?,
        None => None,
    };
    Ok(Loaded {
        recent: newest,
        next_id: max_id + 1,
        rev: rev.unwrap_or(0),
        disk_rev: disk_rev.unwrap_or(0),
        last_seen: last_seen.map(from_millis),
    })
}

/// Unexpired entries matching `query` with an `id` below `below`, newest
/// first, at most `limit`.
fn select(
    conn: &Connection,
    query: &Query,
    horizon: SystemTime,
    below: Option<u64>,
    limit: usize,
) -> rusqlite::Result<Vec<Entry>> {
    let mut sql = String::from(
        "SELECT id, rev, time, last, count, kind, level, subject, message, fields \
         FROM entries WHERE last >= ?1",
    );
    let mut args = vec![int(millis(horizon))];
    let before = match (query.before, below) {
        (Some(before), Some(below)) => Some(before.min(below)),
        (before, below) => before.or(below),
    };
    if let Some(before) = before {
        args.push(int(before));
        let _ = write!(sql, " AND id < ?{}", args.len());
    }
    if let Some(since) = query.since {
        args.push(int(since));
        let _ = write!(sql, " AND rev > ?{}", args.len());
    }
    sql.push_str(match query.level {
        None | Some(Level::Info) => "",
        Some(Level::Warning) => " AND level IN ('warning', 'error')",
        Some(Level::Error) => " AND level = 'error'",
    });
    if let Some(kind) = &query.kind {
        args.push(SqlValue::Text(kind.clone()));
        let n = args.len();
        // The kind, or a kind in its area.
        let _ = write!(
            sql,
            " AND (kind = ?{n} OR substr(kind, 1, length(?{n}) + 1) = ?{n} || '.')"
        );
    }
    if let Some(subject) = &query.subject {
        args.push(SqlValue::Text(subject.clone()));
        let _ = write!(sql, " AND subject = ?{}", args.len());
    }
    args.push(int(u64::try_from(limit).unwrap_or(u64::MAX)));
    let _ = write!(sql, " ORDER BY id DESC LIMIT ?{}", args.len());
    let mut statement = conn.prepare(&sql)?;
    let rows = statement.query_map(params_from_iter(&args), entry_from_row)?;
    rows.collect()
}

fn entry_from_row(row: &Row<'_>) -> rusqlite::Result<Entry> {
    let count: u32 = row.get(4)?;
    let fields: Option<String> = row.get(9)?;
    Ok(Entry {
        id: row.get(0)?,
        rev: row.get(1)?,
        time: from_millis(row.get(2)?),
        last: (count > 1)
            .then(|| row.get(3).map(from_millis))
            .transpose()?,
        count,
        kind: SmolStr::new(row.get_ref(5)?.as_str()?),
        level: row.get_ref(6)?.as_str()?.parse().unwrap_or(Level::Info),
        subject: SmolStr::new(row.get_ref(7)?.as_str()?),
        message: row.get(8)?,
        fields: fields
            .and_then(|fields| serde_json::from_str(&fields).ok())
            .unwrap_or_default(),
    })
}

fn upsert(conn: &Connection, entry: &Entry) -> rusqlite::Result<()> {
    let fields = if entry.fields.is_empty() {
        None
    } else {
        serde_json::to_string(&entry.fields).ok()
    };
    conn.execute(
        UPSERT,
        params![
            entry.id,
            entry.rev,
            millis(entry.time),
            millis(entry.last_time()),
            entry.count,
            entry.kind.as_str(),
            entry.level.as_str(),
            entry.subject.as_str(),
            entry.message,
            fields,
        ],
    )?;
    Ok(())
}

/// Read the logbook in `dir` from another process (see [`super::read`]).
pub fn read(dir: &Path, query: &Query) -> io::Result<Page> {
    read_at(dir, query, SystemTime::now())
}

pub(super) fn read_at(dir: &Path, query: &Query, now: SystemTime) -> io::Result<Page> {
    let path = dir.join(DB_FILE);
    if !path.exists() {
        return Ok(Page::default());
    }
    read_db(&path, query, now).map_err(Unusable::into_io)
}

fn read_db(path: &Path, query: &Query, now: SystemTime) -> Result<Page, Unusable> {
    let conn = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    conn.busy_timeout(BUSY_TIMEOUT)?;
    // One read transaction, so the page and its rev agree.
    let tx = conn.unchecked_transaction()?;
    if schema_version(&tx)? == 0 {
        // Created, and the schema not committed yet.
        return Ok(Page::default());
    }
    let limit = query.page_size();
    let mut entries = select(&tx, query, horizon(now, RETENTION), None, limit + 1)?;
    let rev = tx.query_row("SELECT COALESCE(MAX(rev), 0) FROM entries", [], |row| {
        row.get(0)
    })?;
    let more = entries.len() > limit;
    entries.truncate(limit);
    Ok(Page { entries, rev, more })
}

struct Writer {
    conn: Connection,
    path: PathBuf,
    max_size: u64,
    retention: Duration,
    /// When expired entries were last deleted.
    pruned: SystemTime,
    state: Arc<Mutex<State>>,
    cleared: Arc<AtomicU64>,
    /// Entries below this `id` are deleted.
    deleted_below: u64,
    /// Writes a failed commit kept for the next one, by `id`.
    backlog: BTreeMap<u64, Box<Entry>>,
    /// When to try a failed commit again.
    retry_at: Option<Instant>,
    /// Warned about the current run of failed commits.
    failing: bool,
    /// Warned about the current run of failed deletes and vacuums.
    upkeep_failing: bool,
}

impl Writer {
    fn run(mut self, rx: &Receiver<Op>) {
        let mut wake: Option<Instant> = None;
        loop {
            let received = match wake {
                Some(at) => rx.recv_timeout(at.saturating_duration_since(Instant::now())),
                None => rx.recv().map_err(|_| RecvTimeoutError::Disconnected),
            };
            match received {
                Ok(op) => {
                    let batch = std::iter::once(op)
                        .chain(rx.try_iter().take(BATCH - 1))
                        .collect();
                    self.commit(batch);
                }
                Err(RecvTimeoutError::Timeout) => {}
                Err(RecvTimeoutError::Disconnected) => break,
            }
            // Also between batches: a steady stream of writes must not
            // keep the timer from firing.
            if wake.is_some_and(|at| at <= Instant::now()) {
                if self.retry_at.is_some_and(|at| at <= Instant::now()) {
                    self.commit(Vec::new());
                }
                // Queued under the lock like any write, so they reach the
                // database in `rev` order.
                if let Some(mut state) = self.state.try_lock() {
                    state.write_held(SystemTime::now(), false);
                }
            }
            wake = self.next_wake();
        }
        // The logbook closed: one last try at what failed.
        self.commit(Vec::new());
    }

    /// When to look for held-back repeats or retry a failed commit.
    fn next_wake(&self) -> Option<Instant> {
        let now = Instant::now();
        let held = match self.state.try_lock() {
            // At most a minute away, whatever the clock does.
            Some(state) => state.held_due.map(|due| {
                let wait = due.duration_since(SystemTime::now()).unwrap_or_default();
                now + wait.min(FOLD_WRITE_INTERVAL)
            }),
            // Busy recording: look again shortly.
            None => Some(now + Duration::from_millis(100)),
        };
        match (held, self.retry_at) {
            (Some(held), Some(retry)) => Some(held.min(retry)),
            (held, retry) => held.or(retry),
        }
    }

    /// Commit the backlog, a pending clear and `batch`'s writes in one
    /// transaction, then answer its reads. A failed commit keeps the writes
    /// for the next one.
    fn commit(&mut self, batch: Vec<Op>) {
        let mut writes = std::mem::take(&mut self.backlog);
        let mut selects = Vec::new();
        let mut flushes = Vec::new();
        for op in batch {
            match op {
                Op::Write(entry) => keep_latest(&mut writes, entry),
                Op::Wake => {}
                Op::Select(select) => selects.push(*select),
                Op::Flush(ack) => flushes.push(ack),
            }
        }
        // Read after the batch: a clear stores its bound before it records
        // the entries that follow it.
        let cleared = self.cleared.load(Ordering::Acquire);
        let mut writes = writes.split_off(&cleared);
        let clear = (cleared > self.deleted_below).then_some(cleared);
        if writes.is_empty() && clear.is_none() && selects.is_empty() {
            self.retry_at = None;
        } else {
            match self.transact(&writes, clear, &selects) {
                Ok(reads) => {
                    self.failing = false;
                    self.retry_at = None;
                    for (select, read) in selects.into_iter().zip(reads) {
                        let _ = select.reply.send(read);
                    }
                    if let Some(cleared) = clear {
                        self.deleted_below = cleared;
                        // Deleted entries leave the write-ahead log too.
                        let result = vacuum(&self.conn).and_then(|()| {
                            self.conn
                                .query_row("PRAGMA wal_checkpoint(TRUNCATE)", [], |_| Ok(()))
                        });
                        self.upkeep(result);
                    }
                    let latest = writes.values().map(|entry| entry.last_time()).max();
                    if let Some(now) = latest {
                        if now
                            .duration_since(self.pruned)
                            .is_ok_and(|since| since >= PRUNE_INTERVAL)
                        {
                            self.pruned = now;
                            let result = prune(&self.conn, horizon(now, self.retention));
                            self.upkeep(result);
                        }
                        let result = cap(&self.conn, self.max_size);
                        self.upkeep(result);
                    }
                }
                Err(e) => {
                    if !self.failing {
                        warn!(
                            "logbook: cannot write {}: {e}; trying again",
                            self.path.display()
                        );
                        self.failing = true;
                    }
                    for select in selects {
                        let _ = select.reply.send(Err(io::Error::other(format!(
                            "cannot read the logbook: {e}"
                        ))));
                    }
                    // Bounded like the queue: past it, the oldest go.
                    while writes.len() > QUEUE {
                        writes.pop_first();
                    }
                    self.backlog = writes;
                    self.retry_at = Some(Instant::now() + RETRY_INTERVAL);
                }
            }
        }
        for ack in flushes {
            let _ = ack.send(());
        }
    }

    /// One transaction: the clear, the writes, then the reads, which see
    /// both. Writing takes the lock up front, so a database another
    /// connection holds fails once rather than at every statement.
    fn transact(
        &mut self,
        writes: &BTreeMap<u64, Box<Entry>>,
        clear: Option<u64>,
        selects: &[Select],
    ) -> rusqlite::Result<Vec<io::Result<Vec<Entry>>>> {
        let behavior = if writes.is_empty() && clear.is_none() {
            TransactionBehavior::Deferred
        } else {
            TransactionBehavior::Immediate
        };
        let tx = self.conn.transaction_with_behavior(behavior)?;
        if let Some(cleared) = clear {
            tx.execute("DELETE FROM entries WHERE id < ?1", [cleared])?;
        }
        for entry in writes.values() {
            if let Err(e) = upsert(&tx, entry) {
                if !rejects_entry(&e) {
                    return Err(e);
                }
                warn!("logbook: cannot write entry {}: {e}; dropping it", entry.id);
            }
        }
        let reads = selects
            .iter()
            .map(|s| select(&tx, &s.query, s.horizon, s.below, s.limit).map_err(io::Error::other))
            .collect();
        tx.commit()?;
        Ok(reads)
    }

    fn upkeep(&mut self, result: rusqlite::Result<()>) {
        match result {
            Ok(()) => self.upkeep_failing = false,
            Err(e) => {
                if !self.upkeep_failing {
                    warn!("logbook: cannot maintain {}: {e}", self.path.display());
                    self.upkeep_failing = true;
                }
            }
        }
    }
}

/// Add `entry` to `writes`, unless a later write of it is there already.
fn keep_latest(writes: &mut BTreeMap<u64, Box<Entry>>, entry: Box<Entry>) {
    match writes.entry(entry.id) {
        btree_map::Entry::Vacant(slot) => {
            slot.insert(entry);
        }
        btree_map::Entry::Occupied(mut slot) => {
            if entry.rev > slot.get().rev {
                slot.insert(entry);
            }
        }
    }
}

/// A write that fails for this entry alone, and would again: skipped
/// rather than holding up the rest. Anything else (the lock, the disk)
/// fails the commit, which is tried again.
fn rejects_entry(e: &rusqlite::Error) -> bool {
    e.sqlite_error_code().is_none_or(|code| {
        matches!(
            code,
            ErrorCode::TooBig | ErrorCode::ConstraintViolation | ErrorCode::TypeMismatch
        )
    })
}

/// Delete the entries last seen before `horizon`.
fn prune(conn: &Connection, horizon: SystemTime) -> rusqlite::Result<()> {
    let deleted = conn.execute("DELETE FROM entries WHERE last < ?1", [millis(horizon)])?;
    if deleted > 0 {
        vacuum(conn)?;
    }
    Ok(())
}

/// Delete the oldest entries while the database is over `max_size`, down
/// to three quarters of it so that the next writes do not delete again.
fn cap(conn: &Connection, max_size: u64) -> rusqlite::Result<()> {
    if trim(conn, max_size)? {
        vacuum(conn)?;
    }
    Ok(())
}

/// Whether the database was over `max_size` and the oldest entries were
/// deleted.
fn trim(conn: &Connection, max_size: u64) -> rusqlite::Result<bool> {
    let mut trimmed = false;
    loop {
        let used: u64 = conn.query_row(
            "SELECT (page_count - freelist_count) * page_size \
             FROM pragma_page_count(), pragma_freelist_count(), pragma_page_size()",
            [],
            |row| row.get(0),
        )?;
        if used <= max_size {
            return Ok(trimmed);
        }
        let rows: u64 = conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))?;
        if rows == 0 {
            return Ok(trimmed);
        }
        // In proportion to the bytes over three quarters of the cap.
        let excess = (rows * (used - max_size / 4 * 3) / used).max(1);
        conn.execute(
            "DELETE FROM entries WHERE id IN (SELECT id FROM entries ORDER BY id LIMIT ?1)",
            [excess],
        )?;
        trimmed = true;
    }
}

/// Hand the free pages back to the file system. `incremental_vacuum` frees
/// one page per row it steps, so it runs to the end.
fn vacuum(conn: &Connection) -> rusqlite::Result<()> {
    let mut statement = conn.prepare("PRAGMA incremental_vacuum")?;
    let mut rows = statement.query([])?;
    while rows.next()?.is_some() {}
    Ok(())
}

/// Remove `path`; a missing file is fine.
fn remove(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => warn!("logbook: cannot remove {}: {e}", path.display()),
    }
}

/// The oldest time kept at `now`.
fn horizon(now: SystemTime, retention: Duration) -> SystemTime {
    now.checked_sub(retention).unwrap_or(UNIX_EPOCH)
}

/// Unix milliseconds, the stored time.
fn millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

fn from_millis(ms: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_millis(ms)
}

/// An SQLite integer; ids, revs and times stay far below `i64::MAX`.
fn int(n: u64) -> SqlValue {
    SqlValue::Integer(i64::try_from(n).unwrap_or(i64::MAX))
}

/// `2d 3h`, `3h 12m`, `5m 3s`, `42s`.
pub(super) fn format_uptime(uptime: Duration) -> String {
    let secs = uptime.as_secs();
    let (days, hours, minutes, seconds) =
        (secs / 86_400, secs / 3_600 % 24, secs / 60 % 60, secs % 60);
    if days > 0 {
        format!("{days}d {hours}h")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m {seconds}s")
    } else {
        format!("{seconds}s")
    }
}
