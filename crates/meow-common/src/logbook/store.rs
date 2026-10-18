//! The store behind the logbook: recent entries in memory, every write
//! appended to disk by a writer thread.

use super::{kind, rfc3339, Entry, Event, Level, Options, Stop, COALESCE_WINDOW};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use smol_str::SmolStr;
use std::cmp::Reverse;
use std::collections::{hash_map, HashMap, VecDeque};
use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender, TrySendError};
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tracing::warn;

const CURRENT_FILE: &str = "logbook.jsonl";
const PREVIOUS_FILE: &str = "logbook.1.jsonl";
/// The rotated segment being rewritten by a compaction.
const COMPACT_FILE: &str = "logbook.1.jsonl.tmp";
const LOCK_FILE: &str = "logbook.lock";
/// Present while a run is going; left behind by a run that never stopped.
const RUN_MARKER: &str = "run.json";

/// Lines waiting for the writer thread. Past this, recording drops lines
/// rather than wait on the disk.
const QUEUE: usize = 1024;

/// Page size without `limit`, and the largest page.
pub const DEFAULT_LIMIT: usize = 100;
pub const MAX_LIMIT: usize = 1000;

/// How long [`Logbook::flush`] waits for the writer.
const FLUSH_TIMEOUT: Duration = Duration::from_secs(2);

const VERSION: &str = env!("CARGO_PKG_VERSION");

/// A repeat folded into an entry reaches the disk at most this often. The
/// entry in memory is always current; a crash loses at most this much of
/// its count.
const FOLD_WRITE_INTERVAL: Duration = Duration::from_secs(60);

/// A logbook in one directory. Usually reached through
/// [`super::current`]; see the [module docs](super).
pub struct Logbook {
    dir: PathBuf,
    options: Options,
    state: Mutex<State>,
    queue: Queue,
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
}

struct Slot {
    entry: Entry,
    /// When the entry was last queued for the disk.
    written: SystemTime,
    /// A folded repeat is not queued yet (see [`FOLD_WRITE_INTERVAL`]).
    dirty: bool,
}

/// The writer thread's queue.
struct Queue {
    /// `None` only while dropping, to close the queue.
    tx: Option<SyncSender<Op>>,
    dropped: AtomicU64,
}

enum Op {
    /// A line, and the time it was written at.
    Line(Vec<u8>, SystemTime),
    /// Rewrite the segments without the entries expired at this time.
    Compact(SystemTime),
    Clear,
    Flush(SyncSender<()>),
}

/// Which entries [`Logbook::query`] returns. All conditions must hold.
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

impl Query {
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

#[derive(Serialize, Deserialize)]
struct RunMarker {
    #[serde(with = "rfc3339")]
    started: SystemTime,
    version: String,
}

impl Logbook {
    /// Open the logbook in `dir`, creating it if needed. Fails when another
    /// process holds it.
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

        let horizon = now.checked_sub(options.retention).unwrap_or(UNIX_EPOCH);
        let loaded = load(dir);
        // Expired entries leave the files at the next compaction; a quiet
        // logbook may not fill a segment for weeks, so start one now.
        let expired = loaded
            .entries
            .values()
            .any(|entry| entry.id != loaded.max_id && entry.last_time() < horizon);
        let mut entries: Vec<Entry> = loaded
            .entries
            .into_values()
            .filter(|entry| entry.last_time() >= horizon)
            .collect();
        entries.sort_unstable_by_key(|entry| entry.id);
        let last_seen = entries.iter().map(Entry::last_time).max();
        let split = entries.len().saturating_sub(options.recent);
        let disk_rev = entries[..split]
            .iter()
            .map(|entry| entry.rev)
            .max()
            .unwrap_or(0);
        let recent: VecDeque<Slot> = entries
            .drain(split..)
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

        let writer = Writer {
            dir: dir.to_owned(),
            current: dir.join(CURRENT_FILE),
            previous: dir.join(PREVIOUS_FILE),
            max_size: options.max_size,
            retention: options.retention,
            size: fs::metadata(dir.join(CURRENT_FILE)).map_or(0, |meta| meta.len()),
            file: None,
            failing: false,
        };
        let (tx, rx) = mpsc::sync_channel(QUEUE);
        if expired {
            let _ = tx.try_send(Op::Compact(now));
        }
        let thread = std::thread::Builder::new()
            .name("meow-logbook".into())
            .spawn(move || writer.run(&rx))?;

        Ok(Self {
            dir: dir.to_owned(),
            options,
            state: Mutex::new(State {
                next_id: loaded.max_id + 1,
                rev: loaded.max_rev,
                recent,
                disk_rev,
                latest_by_subject,
                last_seen,
                run_started: None,
            }),
            queue: Queue {
                tx: Some(tx),
                dropped: AtomicU64::new(0),
            },
            writer: Some(thread),
            _lock: lock,
        })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn record(&self, event: Event) {
        self.record_at(event, SystemTime::now());
    }

    pub(super) fn record_at(&self, event: Event, now: SystemTime) -> Entry {
        // Queued under the lock, so an entry's writes reach the file in
        // `rev` order.
        self.state
            .lock()
            .write(event, to_millis(now), &self.options, &self.queue)
    }

    /// Entries matching `query`, newest first. Paging back past the
    /// entries kept in memory reads the files, so call it off the async
    /// runtime.
    pub fn query(&self, query: &Query) -> Page {
        self.query_at(query, SystemTime::now())
    }

    pub(super) fn query_at(&self, query: &Query, now: SystemTime) -> Page {
        let limit = query.limit.unwrap_or(DEFAULT_LIMIT).clamp(1, MAX_LIMIT);
        let horizon = now
            .checked_sub(self.options.retention)
            .unwrap_or(UNIX_EPOCH);
        let (rev, mut entries, disk_rev, oldest_recent) = {
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
            (
                state.rev,
                entries,
                state.disk_rev,
                state.recent.front().map(|slot| slot.entry.id),
            )
        };
        // The entries in memory are current; the files are needed only for
        // the ones that left it, and a poll only when one of those changed
        // since.
        if entries.len() <= limit && query.since.unwrap_or(0) < disk_rev {
            self.queue.flush();
            let mut older: Vec<Entry> = load(&self.dir)
                .entries
                .into_values()
                .filter(|entry| {
                    oldest_recent.is_none_or(|oldest| entry.id < oldest)
                        && entry.last_time() >= horizon
                        && query.matches(entry)
                })
                .collect();
            older.sort_unstable_by_key(|entry| Reverse(entry.id));
            let room = limit + 1 - entries.len();
            entries.extend(older.into_iter().take(room));
        }
        let more = entries.len() > limit;
        entries.truncate(limit);
        Page { entries, rev, more }
    }

    /// Delete every entry, then record that the logbook was cleared. Ids
    /// keep increasing, so a client drops whatever it holds below the
    /// `logbook.cleared` entry.
    pub fn clear(&self) {
        {
            let mut state = self.state.lock();
            state.recent.clear();
            state.latest_by_subject.clear();
            state.disk_rev = 0;
            self.queue.clear();
        }
        self.record(super::event(
            kind::LOGBOOK_CLEARED,
            Level::Info,
            "Cleared the logbook",
        ));
    }

    /// Write out pending repeats and wait (briefly) for the writer.
    pub fn flush(&self) {
        self.state.lock().write_dirty(&self.queue);
        self.queue.flush();
    }

    /// The level of the latest entry of `kind` for `subject`, while that
    /// entry is among the ones kept in memory.
    pub fn latest_level(&self, kind: &str, subject: &str) -> Option<Level> {
        let state = self.state.lock();
        let id = *state
            .latest_by_subject
            .get(&(SmolStr::new(kind), SmolStr::new(subject)))?;
        let i = state
            .recent
            .binary_search_by_key(&id, |slot| slot.entry.id)
            .ok()?;
        Some(state.recent[i].entry.level)
    }

    /// Lines dropped because the writer fell behind.
    pub fn dropped(&self) -> u64 {
        self.queue.dropped.load(Ordering::Relaxed)
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
        self.state.get_mut().write_dirty(&self.queue);
        // Closing the queue lets the writer finish what is queued and exit.
        drop(self.queue.tx.take());
        if let Some(writer) = self.writer.take() {
            let _ = writer.join();
        }
    }
}

impl Queue {
    /// Queue `entry` for the disk, or drop it when the writer is behind.
    fn send(&self, entry: &Entry) {
        let Some(tx) = &self.tx else {
            return;
        };
        let mut line = serde_json::to_vec(entry).unwrap_or_default();
        line.push(b'\n');
        match tx.try_send(Op::Line(line, entry.last_time())) {
            Ok(()) | Err(TrySendError::Disconnected(_)) => {}
            Err(TrySendError::Full(_)) => {
                if self.dropped.fetch_add(1, Ordering::Relaxed) == 0 {
                    warn!("logbook: the writer fell behind; dropping entries");
                }
            }
        }
    }

    fn clear(&self) {
        if let Some(tx) = &self.tx {
            let _ = tx.send(Op::Clear);
        }
    }

    /// Wait (briefly) until the writer has written everything queued.
    fn flush(&self) {
        let Some(tx) = &self.tx else {
            return;
        };
        let (ack, done) = mpsc::sync_channel(1);
        if tx.send(Op::Flush(ack)).is_ok() {
            let _ = done.recv_timeout(FLUSH_TIMEOUT);
        }
    }
}

impl State {
    fn write(&mut self, event: Event, now: SystemTime, options: &Options, queue: &Queue) -> Entry {
        // Never below the clock, so revs keep increasing across a restart
        // even past writes a crash lost.
        self.rev = (self.rev + 1).max(unix_millis(now));
        self.last_seen = Some(now);
        if event.coalesce {
            if let Some(i) = self.fold_target(&event, now) {
                let slot = &mut self.recent[i];
                let entry = &mut slot.entry;
                entry.rev = self.rev;
                entry.count = entry.count.saturating_add(1);
                entry.last = Some(now);
                entry.message = event.message;
                entry.fields = event.fields;
                let due = !now
                    .duration_since(slot.written)
                    .is_ok_and(|since| since < FOLD_WRITE_INTERVAL);
                if due {
                    queue.send(&slot.entry);
                    slot.written = now;
                }
                slot.dirty = !due;
                return slot.entry.clone();
            }
        }
        let entry = Entry {
            id: self.next_id,
            rev: self.rev,
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
        queue.send(&entry);
        self.latest_by_subject
            .insert((entry.kind.clone(), entry.subject.clone()), entry.id);
        self.recent.push_back(Slot {
            entry: entry.clone(),
            written: now,
            dirty: false,
        });
        if self.recent.len() > options.recent {
            if let Some(evicted) = self.recent.pop_front() {
                if evicted.dirty {
                    queue.send(&evicted.entry);
                }
                self.disk_rev = self.disk_rev.max(evicted.entry.rev);
            }
            if self.latest_by_subject.len() > 4 * options.recent {
                let oldest = self.recent.front().map_or(0, |slot| slot.entry.id);
                self.latest_by_subject.retain(|_, id| *id >= oldest);
            }
        }
        entry
    }

    /// Queue the repeats [`FOLD_WRITE_INTERVAL`] held back.
    fn write_dirty(&mut self, queue: &Queue) {
        for slot in self.recent.iter_mut().filter(|slot| slot.dirty) {
            queue.send(&slot.entry);
            slot.dirty = false;
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

#[derive(Default)]
struct Loaded {
    /// The latest write of each entry.
    entries: HashMap<u64, Entry>,
    max_id: u64,
    max_rev: u64,
}

/// Read both segments, skipping lines that do not parse (a torn write).
fn load(dir: &Path) -> Loaded {
    let mut loaded = Loaded::default();
    for name in [PREVIOUS_FILE, CURRENT_FILE] {
        let Ok(bytes) = fs::read(dir.join(name)) else {
            continue;
        };
        for line in bytes.split(|b| *b == b'\n') {
            let Ok(entry) = serde_json::from_slice::<Entry>(line) else {
                continue;
            };
            loaded.max_id = loaded.max_id.max(entry.id);
            loaded.max_rev = loaded.max_rev.max(entry.rev);
            match loaded.entries.entry(entry.id) {
                hash_map::Entry::Occupied(mut slot) => {
                    if slot.get().rev < entry.rev {
                        slot.insert(entry);
                    }
                }
                hash_map::Entry::Vacant(slot) => {
                    slot.insert(entry);
                }
            }
        }
    }
    loaded
}

struct Writer {
    dir: PathBuf,
    current: PathBuf,
    previous: PathBuf,
    max_size: u64,
    retention: Duration,
    /// Bytes in the current segment.
    size: u64,
    file: Option<File>,
    /// Logged the current run of write errors already.
    failing: bool,
}

impl Writer {
    fn run(mut self, rx: &Receiver<Op>) {
        for op in rx {
            match op {
                Op::Line(line, now) => self.append(&line, now),
                Op::Compact(now) => self.compact(now),
                Op::Clear => self.clear(),
                Op::Flush(ack) => {
                    let _ = ack.send(());
                }
            }
        }
    }

    fn append(&mut self, line: &[u8], now: SystemTime) {
        let len = line.len() as u64;
        // Each segment holds half the cap, so the two stay under it.
        if self.size > 0 && self.size + len > self.max_size / 2 {
            self.compact(now);
        }
        match self.open().and_then(|file| file.write_all(line)) {
            Ok(()) => {
                self.size += len;
                self.failing = false;
            }
            Err(e) => {
                self.file = None;
                if !self.failing {
                    warn!("logbook: cannot write {}: {e}", self.current.display());
                    self.failing = true;
                }
            }
        }
    }

    fn open(&mut self) -> io::Result<&mut File> {
        let file = match self.file.take() {
            Some(file) => file,
            None => {
                let mut file = OpenOptions::new()
                    .create(true)
                    .read(true)
                    .append(true)
                    .open(&self.current)?;
                self.size = file.metadata()?.len();
                // End a line torn by a crash or a failed write, so the next
                // line is not glued to it and lost with it.
                if self.size > 0 && !ends_with_newline(&mut file)? {
                    file.write_all(b"\n")?;
                    self.size += 1;
                }
                file
            }
        };
        Ok(self.file.insert(file))
    }

    /// Rewrite both segments into the rotated one and start the current
    /// one empty. The rewrite keeps the latest write of each entry, so an
    /// entry folded a thousand times is one line again, and the newest
    /// entries that fit in half the cap, minus the ones past the retention.
    fn compact(&mut self, now: SystemTime) {
        self.file = None;
        let horizon = now.checked_sub(self.retention).unwrap_or(UNIX_EPOCH);
        let loaded = load(&self.dir);
        let max_id = loaded.max_id;
        let mut entries: Vec<Entry> = loaded
            .entries
            .into_values()
            // The highest id stays even when expired: the next id follows
            // it.
            .filter(|entry| entry.id == max_id || entry.last_time() >= horizon)
            .collect();
        entries.sort_unstable_by_key(|entry| Reverse(entry.id));
        let mut lines = Vec::new();
        let mut size = 0;
        for entry in &entries {
            let Ok(mut line) = serde_json::to_vec(entry) else {
                continue;
            };
            line.push(b'\n');
            size += line.len() as u64;
            if size > self.max_size / 2 {
                break;
            }
            lines.push(line);
        }
        let tmp = self.dir.join(COMPACT_FILE);
        let rewritten = File::create(&tmp)
            .and_then(|mut file| lines.iter().rev().try_for_each(|line| file.write_all(line)))
            .and_then(|()| fs::rename(&tmp, &self.previous));
        match rewritten {
            Ok(()) => remove(&self.current),
            Err(e) => {
                // Out of space, most likely: rotate as is, which needs none.
                warn!("logbook: cannot compact {}: {e}", self.dir.display());
                remove(&tmp);
                if let Err(e) = fs::rename(&self.current, &self.previous) {
                    if e.kind() != io::ErrorKind::NotFound {
                        warn!("logbook: cannot rotate {}: {e}", self.current.display());
                    }
                }
            }
        }
        self.size = 0;
    }

    fn clear(&mut self) {
        self.file = None;
        remove(&self.previous);
        remove(&self.current);
        self.size = 0;
    }
}

fn ends_with_newline(file: &mut File) -> io::Result<bool> {
    let mut last = [0];
    file.seek(SeekFrom::End(-1))?;
    file.read_exact(&mut last)?;
    Ok(last[0] == b'\n')
}

/// Remove `path`; a missing file is fine.
fn remove(path: &Path) {
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => warn!("logbook: cannot remove {}: {e}", path.display()),
    }
}

fn unix_millis(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH).map_or(0, |since| {
        u64::try_from(since.as_millis()).unwrap_or(u64::MAX)
    })
}

/// `t` rounded down to whole milliseconds, the stored precision.
pub(super) fn to_millis(t: SystemTime) -> SystemTime {
    t.duration_since(UNIX_EPOCH).map_or(UNIX_EPOCH, |since| {
        UNIX_EPOCH + Duration::new(since.as_secs(), since.subsec_millis() * 1_000_000)
    })
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
