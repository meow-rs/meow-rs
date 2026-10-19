use super::store::{format_uptime, read_at, Logbook};
use super::*;
use std::fs;
use std::time::Instant;

/// 2100-01-01T00:00:00Z: far enough ahead that the writer's timer, which
/// runs on the real clock, never finds a repeat held back here due.
fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(4_102_444_800)
}

fn at(secs: u64) -> SystemTime {
    t0() + Duration::from_secs(secs)
}

fn open(dir: &Path, now: SystemTime) -> Logbook {
    Logbook::open_at(dir, Options::default(), now).unwrap()
}

fn small(recent: usize, max_size: u64) -> Options {
    Options {
        recent,
        max_size,
        ..Options::default()
    }
}

fn info(message: &str) -> Event {
    event("test.info", Level::Info, message)
}

fn failure(subject: &str, message: &str) -> Event {
    event("rule-provider.update", Level::Error, message)
        .subject(subject)
        .coalesce()
}

fn all(book: &Logbook, now: SystemTime) -> Vec<Entry> {
    book.query_at(
        &Query {
            limit: Some(MAX_LIMIT),
            ..Query::default()
        },
        now,
    )
    .unwrap()
    .entries
}

/// Everything on disk, read as another process would.
fn on_disk(dir: &Path, now: SystemTime) -> Vec<Entry> {
    let query = Query {
        limit: Some(MAX_LIMIT),
        ..Query::default()
    };
    read_at(dir, &query, now).unwrap().entries
}

/// Rows in the database, expired or not.
fn rows(dir: &Path) -> u64 {
    let conn = rusqlite::Connection::open(dir.join("logbook.db")).unwrap();
    conn.query_row("SELECT COUNT(*) FROM entries", [], |row| row.get(0))
        .unwrap()
}

fn messages(entries: &[Entry]) -> Vec<&str> {
    entries.iter().map(|e| e.message.as_str()).collect()
}

#[test]
fn entries_survive_a_reopen_and_ids_keep_increasing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(info("one"), at(1));
        book.record_at(info("two").field("proxies", 84), at(2));
    }
    let book = open(dir.path(), at(10));
    let entries = all(&book, at(10));
    assert_eq!(messages(&entries), ["two", "one"], "newest first");
    assert_eq!(entries[0].fields["proxies"], 84);
    assert_eq!(entries[0].time, at(2));
    // Even with the clock set back.
    let three = book.record_at(info("three"), at(0));
    assert_eq!(three.id, 3);
    assert!(three.rev > entries[0].rev);
}

#[test]
fn an_entry_serializes_to_the_documented_shape() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    let entry = book.record_at(
        event("config.reload", Level::Error, "Reload failed").field("error", "bad yaml"),
        t0() + Duration::from_nanos(123_456_789),
    );
    let json = serde_json::to_value(&entry).unwrap();
    assert_eq!(
        json,
        serde_json::json!({
            "id": 1,
            "rev": 4_102_444_800_123_u64,
            "time": "2100-01-01T00:00:00.123Z",
            "count": 1,
            "kind": "config.reload",
            "level": "error",
            "message": "Reload failed",
            "fields": { "error": "bad yaml" },
        })
    );
}

#[test]
fn repeats_fold_into_the_subjects_latest_entry() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(failure("rules", "timed out"), at(0));
        book.record_at(failure("rules", "refused"), at(60));
        book.record_at(failure("other", "timed out"), at(61));
        // Another kind about the same subject does not interrupt the fold.
        book.record_at(
            event("config.change", Level::Info, "changed").subject("rules"),
            at(62),
        );
        let folded = book.record_at(failure("rules", "reset"), at(120));
        assert_eq!(folded.id, 1);
        assert_eq!(folded.count, 3);
        assert_eq!(folded.last, Some(at(120)));
        assert_eq!(folded.message, "reset", "the latest occurrence's message");
    }
    let book = open(dir.path(), at(130));
    let entries = all(&book, at(130));
    assert_eq!(entries.len(), 3, "folds persist as one entry");
    assert_eq!((entries[2].id, entries[2].count), (1, 3));
    // A fold after a reopen still lands in the same entry.
    assert_eq!(book.record_at(failure("rules", "again"), at(140)).count, 4);
}

#[test]
fn a_repeat_reaches_the_disk_at_most_once_a_minute() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(failure("rules", "a"), at(0));
        book.record_at(failure("rules", "b"), at(1));
        book.record_at(failure("rules", "c"), at(2));
        assert_eq!(all(&book, at(3))[0].count, 3, "memory is current");
        book.settle();
        assert_eq!(on_disk(dir.path(), at(3))[0].count, 1, "held back");
        book.record_at(failure("rules", "d"), at(61));
        book.settle();
        assert_eq!(on_disk(dir.path(), at(62))[0].count, 4, "due again");
        book.record_at(failure("rules", "e"), at(62));
    }
    // Held-back repeats are written when the logbook closes.
    let book = open(dir.path(), at(70));
    let entry = &all(&book, at(70))[0];
    assert_eq!((entry.count, entry.message.as_str()), (5, "e"));
}

#[test]
fn a_held_back_repeat_reaches_a_reader_polling_the_database() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(failure("rules", "a"), at(0));
    book.record_at(failure("rules", "b"), at(1));
    book.record_at(info("later"), at(2));
    book.settle();
    let poll = |since| {
        let query = Query {
            since: Some(since),
            ..Query::default()
        };
        read_at(dir.path(), &query, at(3)).unwrap()
    };
    let first = poll(0);
    assert_eq!(messages(&first.entries), ["later", "a"], "b held back");
    // Written out after `later`: a newer rev than the reader has seen.
    book.flush();
    let next = poll(first.rev);
    assert_eq!(messages(&next.entries), ["b"]);
    assert_eq!(next.entries[0].count, 2);
}

#[test]
fn a_held_back_repeat_is_written_once_due_without_another_event() {
    let dir = tempfile::tempdir().unwrap();
    // The writer's timer runs on the real clock.
    let now = SystemTime::now();
    let ago = |secs| now - Duration::from_secs(secs);
    let book = open(dir.path(), ago(200));
    book.record_at(failure("rules", "a"), ago(120));
    book.record_at(failure("rules", "b"), ago(100));
    let deadline = Instant::now() + Duration::from_secs(5);
    let count = || on_disk(dir.path(), now).first().map_or(0, |e| e.count);
    while count() < 2 {
        assert!(
            Instant::now() < deadline,
            "the repeat never reached the disk"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    drop(book);
}

#[test]
fn a_held_back_repeat_is_written_when_its_entry_leaves_memory() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = Logbook::open_at(dir.path(), small(1, MAX_SIZE), t0()).unwrap();
        book.record_at(failure("rules", "a"), at(0));
        book.record_at(failure("rules", "b"), at(1));
        book.record_at(info("evicts it"), at(2));
    }
    let book = open(dir.path(), at(10));
    assert_eq!(all(&book, at(10))[1].count, 2);
}

#[test]
fn another_outcome_for_the_subject_or_a_long_gap_starts_a_new_entry() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(failure("rules", "failed"), at(0));
    book.record_at(
        event("rule-provider.update", Level::Info, "updated").subject("rules"),
        at(10),
    );
    assert_eq!(book.record_at(failure("rules", "failed"), at(20)).count, 1);
    let late = at(20) + COALESCE_WINDOW + Duration::from_secs(1);
    assert_eq!(book.record_at(failure("rules", "failed"), late).count, 1);
    assert_eq!(all(&book, late).len(), 4);
}

#[test]
fn the_database_stays_under_its_cap_and_keeps_the_newest() {
    let dir = tempfile::tempdir().unwrap();
    let max_size = 64 * 1024;
    {
        let book = Logbook::open_at(dir.path(), small(8, max_size), t0()).unwrap();
        for i in 0..2000 {
            book.record_at(
                info(&format!("entry {i}")).field("detail", "x".repeat(100)),
                at(i),
            );
            // Faster than any engine records: let the writer keep up
            // rather than drop.
            if i % 100 == 99 {
                book.settle();
            }
        }
    }
    // Closed: the write-ahead log is checkpointed into the database.
    let size = fs::metadata(dir.path().join("logbook.db")).unwrap().len();
    assert!(size <= max_size, "{size} bytes");
    let book = Logbook::open_at(dir.path(), small(8, max_size), at(3000)).unwrap();
    let entries = all(&book, at(3000));
    assert_eq!(entries[0].message, "entry 1999");
    assert!(entries.len() > 8, "pages back into the database");
    assert!(entries.len() < 1000, "the oldest were deleted");
    assert!(
        entries.windows(2).all(|w| w[0].id == w[1].id + 1),
        "a contiguous run of the newest entries"
    );
}

#[test]
fn entries_past_the_retention_are_dropped() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(info("old"), at(0));
        book.record_at(info("new"), at(2 * 24 * 3600));
    }
    let now = at(8 * 24 * 3600);
    let book = open(dir.path(), now);
    assert_eq!(messages(&all(&book, now)), ["new"]);
}

#[test]
fn expired_entries_leave_the_database_but_ids_keep_increasing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        for i in 0..20 {
            book.record_at(info(&format!("entry {i}")), at(i));
        }
    }
    drop(open(dir.path(), at(6 * 24 * 3600)));
    assert_eq!(rows(dir.path()), 20, "still within the retention");
    let now = at(8 * 24 * 3600);
    {
        let book = open(dir.path(), now);
        assert!(all(&book, now).is_empty());
    }
    assert_eq!(rows(dir.path()), 0);
    let book = open(dir.path(), now);
    assert_eq!(
        book.record_at(info("next"), now).id,
        21,
        "ids keep increasing"
    );
}

#[test]
fn a_running_logbook_deletes_what_expires() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(info("old"), at(0));
    book.record_at(info("new"), at(8 * 24 * 3600));
    book.settle();
    assert_eq!(rows(dir.path()), 1);
}

#[test]
fn an_unreadable_database_is_set_aside_and_the_logbook_starts_over() {
    let dir = tempfile::tempdir().unwrap();
    let garbage = b"this is not an SQLite database".repeat(10);
    fs::write(dir.path().join("logbook.db"), &garbage).unwrap();
    let book = open(dir.path(), t0());
    let entries = all(&book, t0());
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, kind::LOGBOOK_RESET);
    assert_eq!(entries[0].level, Level::Warning);
    assert_eq!(entries[0].id, 1);
    assert_eq!(
        fs::read(dir.path().join("logbook.db.corrupt")).unwrap(),
        garbage
    );
    assert_eq!(book.record_at(info("next"), at(1)).id, 2);
}

#[test]
fn a_database_from_a_newer_meow_is_left_alone() {
    let newer = tempfile::tempdir().unwrap();
    let dir = tempfile::tempdir().unwrap();
    let files = ["logbook.db", "logbook.db-wal"];
    {
        let conn = rusqlite::Connection::open(newer.path().join("logbook.db")).unwrap();
        conn.execute_batch(
            "PRAGMA journal_mode = WAL; PRAGMA wal_autocheckpoint = 0;
             CREATE TABLE entries (id INTEGER PRIMARY KEY, future TEXT);
             INSERT INTO entries VALUES (1, 'x');
             PRAGMA user_version = 99;",
        )
        .unwrap();
        // What a newer meow that was killed leaves behind: its writes
        // still in the write-ahead log.
        for name in files {
            fs::copy(newer.path().join(name), dir.path().join(name)).unwrap();
        }
    }
    let before = files.map(|name| fs::read(dir.path().join(name)).unwrap());
    let opened = Logbook::open_at(dir.path(), Options::default(), t0());
    assert_eq!(
        opened.err().map(|e| e.kind()),
        Some(io::ErrorKind::InvalidData)
    );
    assert!(read_at(dir.path(), &Query::default(), t0()).is_err());
    assert!(!dir.path().join("logbook.db.corrupt").exists());
    // Not even checkpointed.
    let after = files.map(|name| fs::read(dir.path().join(name)).unwrap());
    assert!(before == after, "the files changed");
}

#[test]
fn a_row_meow_cannot_read_sets_the_database_aside() {
    let dir = tempfile::tempdir().unwrap();
    drop(open(dir.path(), t0()).record_at(info("one"), at(1)));
    {
        let conn = rusqlite::Connection::open(dir.path().join("logbook.db")).unwrap();
        conn.execute("UPDATE entries SET count = 'many'", [])
            .unwrap();
    }
    let book = open(dir.path(), at(2));
    let entries = all(&book, at(2));
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].kind, kind::LOGBOOK_RESET);
    assert!(dir.path().join("logbook.db.corrupt").exists());
}

#[test]
fn a_killed_process_keeps_what_was_committed() {
    let dir = tempfile::tempdir().unwrap();
    let copy = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(info("committed"), at(1));
    book.settle();
    // What a killed process leaves behind: the database and its
    // write-ahead log, not checkpointed.
    for name in ["logbook.db", "logbook.db-wal"] {
        fs::copy(dir.path().join(name), copy.path().join(name)).unwrap();
    }
    let reopened = open(copy.path(), at(2));
    assert_eq!(messages(&all(&reopened, at(2))), ["committed"]);
}

#[test]
fn another_process_reads_what_was_committed() {
    let dir = tempfile::tempdir().unwrap();
    assert!(on_disk(dir.path(), t0()).is_empty(), "no database yet");
    assert!(!dir.path().join("logbook.db").exists(), "and none created");

    let book = Logbook::open_at(dir.path(), small(2, MAX_SIZE), t0()).unwrap();
    for i in 0..5 {
        let level = if i % 2 == 0 {
            Level::Info
        } else {
            Level::Error
        };
        book.record_at(
            event("rule-provider.update", level, format!("p{i}")).subject("s"),
            at(i),
        );
    }
    let last = book.record_at(info("last"), at(5));
    book.settle();
    let read = |query: Query| read_at(dir.path(), &query, at(10)).unwrap();
    let page = read(Query {
        limit: Some(2),
        ..Query::default()
    });
    assert_eq!(messages(&page.entries), ["last", "p4"]);
    assert!(page.more);
    assert_eq!(page.rev, last.rev);
    let errors = read(Query {
        level: Some(Level::Error),
        kind: Some("rule-provider".into()),
        ..Query::default()
    });
    assert_eq!(messages(&errors.entries), ["p3", "p1"]);
    assert!(!errors.more);
}

#[test]
fn entries_in_memory_expire_too() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(info("old"), at(0));
    book.record_at(info("new"), at(2 * 24 * 3600));
    assert_eq!(messages(&all(&book, at(8 * 24 * 3600))), ["new"]);
}

#[test]
fn the_latest_level_follows_the_subjects_latest_entry() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    let kind = "rule-provider.update";
    assert_eq!(book.latest_level(kind, "rules"), None);
    book.record_at(failure("rules", "failed"), at(0));
    assert_eq!(book.latest_level(kind, "rules"), Some(Level::Error));
    assert_eq!(
        book.latest_level("config.change", "rules"),
        None,
        "per kind"
    );
    book.record_at(event(kind, Level::Info, "updated").subject("rules"), at(1));
    assert_eq!(book.latest_level(kind, "rules"), Some(Level::Info));
}

#[test]
fn an_expired_failure_is_no_longer_the_latest_level() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    let kind = "rule-provider.update";
    book.record_at(failure("rules", "failed"), at(0));
    assert_eq!(
        book.latest_level_at(kind, "rules", at(1)),
        Some(Level::Error)
    );
    let later = at(0) + RETENTION + Duration::from_secs(1);
    assert_eq!(book.latest_level_at(kind, "rules", later), None);
}

#[test]
fn a_second_open_of_the_same_directory_fails() {
    let dir = tempfile::tempdir().unwrap();
    let first = open(dir.path(), t0());
    let second = Logbook::open_at(dir.path(), Options::default(), t0());
    assert_eq!(
        second.err().map(|e| e.kind()),
        Some(io::ErrorKind::WouldBlock)
    );
    drop(first);
    assert!(Logbook::open_at(dir.path(), Options::default(), t0()).is_ok());
}

#[test]
fn a_run_that_never_stopped_is_reported_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.engine_started("/etc/meow/config.yaml", at(0));
        book.record_at(info("last sign of life"), at(50));
        // Killed: no engine_stopped.
    }
    let book = open(dir.path(), at(100));
    book.engine_started("/etc/meow/config.yaml", at(100));
    let entries = all(&book, at(100));
    assert_eq!(entries[0].kind, kind::ENGINE_START);
    let unclean = &entries[1];
    assert_eq!(unclean.kind, kind::ENGINE_UNCLEAN_EXIT);
    assert_eq!(unclean.level, Level::Warning);
    assert_eq!(unclean.fields["started"], "2100-01-01T00:00:00Z");
    assert_eq!(unclean.fields["lastSeen"], "2100-01-01T00:00:50Z");
    assert_eq!(entries[0].fields["config"], "/etc/meow/config.yaml");
}

#[test]
fn a_clean_stop_reports_nothing_at_the_next_start() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.engine_started("inline", at(0));
        book.engine_stopped(Stop::Requested("SIGTERM"), at(3 * 3600 + 12 * 60));
    }
    let book = open(dir.path(), at(20_000));
    book.engine_started("inline", at(20_000));
    let entries = all(&book, at(20_000));
    let kinds: Vec<&str> = entries.iter().map(|e| e.kind.as_str()).collect();
    assert_eq!(
        kinds,
        [kind::ENGINE_START, kind::ENGINE_STOP, kind::ENGINE_START]
    );
    assert_eq!(entries[1].message, "Stopped after 3h 12m (SIGTERM)");
    assert_eq!(entries[1].fields["uptime"], 3 * 3600 + 12 * 60);
    assert_eq!(entries[1].fields["reason"], "SIGTERM");
}

#[test]
fn a_run_that_failed_ended_cleanly() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.engine_started("inline", at(0));
        book.engine_stopped(Stop::Failed("dns.listen: address in use"), at(1));
        let stop = &all(&book, at(1))[0];
        assert_eq!(stop.level, Level::Error);
        assert_eq!(stop.message, "Stopped after 1s: dns.listen: address in use");
    }
    let book = open(dir.path(), at(10));
    book.engine_started("inline", at(10));
    assert!(all(&book, at(10))
        .iter()
        .all(|e| e.kind != kind::ENGINE_UNCLEAN_EXIT));
}

#[test]
fn queries_filter_page_back_and_poll() {
    let dir = tempfile::tempdir().unwrap();
    let book = Logbook::open_at(dir.path(), small(4, MAX_SIZE), t0()).unwrap();
    for i in 0..10 {
        let level = if i % 2 == 0 {
            Level::Info
        } else {
            Level::Error
        };
        book.record_at(
            event("rule-provider.update", level, format!("p{i}")).subject(format!("s{}", i % 3)),
            at(i),
        );
    }
    book.record_at(
        event("rule-providers.other", Level::Info, "x").subject("s0"),
        at(10),
    );

    let page = |query: Query| book.query_at(&query, at(20)).unwrap();
    let first = page(Query {
        limit: Some(3),
        ..Query::default()
    });
    assert_eq!(messages(&first.entries), ["x", "p9", "p8"]);
    assert!(first.more);
    assert_eq!(first.rev, first.entries[0].rev);

    // Paging back crosses from memory (4 entries) into the database.
    let second = page(Query {
        limit: Some(5),
        before: Some(first.entries[2].id),
        ..Query::default()
    });
    assert_eq!(messages(&second.entries), ["p7", "p6", "p5", "p4", "p3"]);
    assert!(second.more);

    let errors = page(Query {
        level: Some(Level::Error),
        ..Query::default()
    });
    assert_eq!(messages(&errors.entries), ["p9", "p7", "p5", "p3", "p1"]);
    assert!(!errors.more);

    let area = page(Query {
        kind: Some("rule-provider".into()),
        subject: Some("s0".into()),
        ..Query::default()
    });
    assert_eq!(
        messages(&area.entries),
        ["p9", "p6", "p3", "p0"],
        "`rule-provider` is an area: it does not match `rule-providers.other`"
    );

    // A repeat folds into p7, which the next entry pushes out of memory: a
    // poll still sees both.
    book.record_at(failure("s1", "folded"), at(21));
    let new = book.record_at(info("new"), at(22));
    let poll = page(Query {
        since: Some(first.rev),
        ..Query::default()
    });
    assert_eq!(messages(&poll.entries), ["new", "folded"]);
    assert_eq!(poll.entries[1].count, 2);
    assert_eq!(poll.rev, new.rev);
    let quiet = page(Query {
        since: Some(poll.rev),
        ..Query::default()
    });
    assert!(quiet.entries.is_empty());
}

#[test]
fn clearing_deletes_everything_but_ids_keep_increasing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = Logbook::open_at(dir.path(), small(2, MAX_SIZE), t0()).unwrap();
        for i in 0..5 {
            book.record_at(info(&format!("e{i}")), at(i));
        }
        book.clear();
        // Recorded at the real time, not the test clock.
        let entries = all(&book, SystemTime::now());
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].kind, kind::LOGBOOK_CLEARED);
        assert_eq!(entries[0].id, 6);
        book.flush();
    }
    let book = open(dir.path(), SystemTime::now());
    let entries = all(&book, SystemTime::now());
    assert_eq!(
        entries.iter().map(|e| e.kind.as_str()).collect::<Vec<_>>(),
        [kind::LOGBOOK_CLEARED]
    );
}

/// Another process holding the database's write lock, as a reader that
/// opened it for writing could.
fn lock_database(dir: &Path) -> rusqlite::Connection {
    let conn = rusqlite::Connection::open(dir.join("logbook.db")).unwrap();
    conn.execute_batch("BEGIN IMMEDIATE").unwrap();
    conn
}

#[test]
fn writes_refused_by_a_locked_database_are_tried_again() {
    let dir = tempfile::tempdir().unwrap();
    let book = Logbook::open_at(dir.path(), small(1, MAX_SIZE), t0()).unwrap();
    book.record_at(info("one"), at(1));
    book.settle();
    let lock = lock_database(dir.path());
    let two = book.record_at(info("two"), at(2));
    // Past memory, so it needs the database.
    let past = Query {
        before: Some(two.id),
        ..Query::default()
    };
    assert!(book.query_at(&past, at(3)).is_err());
    drop(lock);
    book.settle();
    assert_eq!(messages(&on_disk(dir.path(), at(3))), ["two", "one"]);
    assert_eq!(
        messages(&book.query_at(&past, at(3)).unwrap().entries),
        ["one"]
    );
}

#[test]
fn a_clear_while_the_database_is_locked_still_clears() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    for i in 0..3 {
        book.record(info(&format!("committed {i}")));
    }
    book.settle();
    let lock = lock_database(dir.path());
    book.record(info("queued"));
    book.clear();
    book.record(info("after"));
    drop(lock);
    book.settle();
    assert_eq!(
        messages(&on_disk(dir.path(), SystemTime::now())),
        ["after", "Cleared the logbook"]
    );
    assert_eq!(rows(dir.path()), 2);
}

/// Hold the writer up on a locked database, behind a full queue. The
/// returned lock releases it.
fn stall_writer(book: &Logbook, dir: &Path) -> rusqlite::Connection {
    let lock = lock_database(dir);
    book.record(info("holds the writer up"));
    book.fill_queue();
    lock
}

/// Release `lock` from another thread while the caller waits on the
/// writer.
fn release_soon(lock: rusqlite::Connection) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        drop(lock);
    })
}

#[test]
fn a_write_a_full_queue_refused_is_tried_again_at_once() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    let lock = stall_writer(&book, dir.path());
    book.record_at(info("refused"), at(1));
    drop(lock);
    // No flush: the writer retries it on its own.
    let deadline = Instant::now() + Duration::from_secs(5);
    while !messages(&on_disk(dir.path(), at(2))).contains(&"refused") {
        assert!(
            Instant::now() < deadline,
            "the refused write never reached the disk"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[test]
fn a_flush_behind_a_full_queue_writes_the_held_back_repeats() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(failure("rules", "a"), at(0));
    book.settle();
    book.record_at(failure("rules", "b"), at(1));
    let release = release_soon(stall_writer(&book, dir.path()));
    book.flush();
    release.join().unwrap();
    let entries = on_disk(dir.path(), at(2));
    let rules = entries.iter().find(|e| e.subject == "rules").unwrap();
    assert_eq!(rules.count, 2);
}

#[test]
fn a_clear_behind_a_full_queue_writes_its_entry_before_returning() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record(info("one"));
    book.settle();
    let release = release_soon(stall_writer(&book, dir.path()));
    book.clear();
    release.join().unwrap();
    assert_eq!(
        messages(&on_disk(dir.path(), SystemTime::now())),
        ["Cleared the logbook"]
    );
}

#[test]
fn a_held_back_repeat_with_nothing_after_it_keeps_its_rev() {
    let dir = tempfile::tempdir().unwrap();
    let book = open(dir.path(), t0());
    book.record_at(failure("rules", "a"), at(0));
    book.settle();
    let b = book.record_at(failure("rules", "b"), at(1));
    let since = |rev| Query {
        since: Some(rev),
        ..Query::default()
    };
    let seen = book.query_at(&since(0), at(2)).unwrap();
    assert_eq!((seen.rev, seen.entries[0].count), (b.rev, 2));
    let disk = read_at(dir.path(), &since(0), at(2)).unwrap();
    assert_eq!(disk.entries[0].count, 1, "held back");
    book.flush();
    // No rev was handed out after the fold, so a reader that polled at it
    // is not shown the entry again, and one polling the database still is.
    assert!(book
        .query_at(&since(seen.rev), at(2))
        .unwrap()
        .entries
        .is_empty());
    let next = read_at(dir.path(), &since(disk.rev), at(2)).unwrap();
    assert_eq!((next.entries[0].rev, next.entries[0].count), (b.rev, 2));
}

#[test]
fn long_messages_are_cut_at_a_char_boundary() {
    let long = "界".repeat(MAX_MESSAGE);
    let e = event("test.info", Level::Info, long.clone()).field("error", long);
    assert!(e.message.len() <= MAX_MESSAGE);
    assert!(e.message.ends_with('…'));
    let field = e.fields["error"].as_str().unwrap();
    assert!(field.len() <= MAX_MESSAGE && field.ends_with('…'));
}

#[test]
fn uptimes_read_naturally() {
    let f = |secs| format_uptime(Duration::from_secs(secs));
    assert_eq!(f(42), "42s");
    assert_eq!(f(5 * 60 + 3), "5m 3s");
    assert_eq!(f(3 * 3600 + 12 * 60 + 9), "3h 12m");
    assert_eq!(f(2 * 86_400 + 3 * 3600), "2d 3h");
}

#[test]
fn levels_parse_and_order_by_severity() {
    assert_eq!("warning".parse::<Level>(), Ok(Level::Warning));
    assert!("debug".parse::<Level>().is_err());
    assert!(Level::Info < Level::Warning && Level::Warning < Level::Error);
}

/// The only test that installs the process-wide logbook. Tests elsewhere
/// in the crate record into it while it is installed (`outbound_iface`), so
/// it looks at its own kinds only.
#[test]
fn the_installed_logbook_records_and_watches_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("run.json");
    info("before install").record();
    install(dir.path(), Options::default()).unwrap();
    assert!(enabled());
    let book = current().unwrap();
    install(dir.path(), Options::default()).unwrap();
    assert!(Arc::ptr_eq(&book, &current().unwrap()), "kept");
    engine_started("inline");
    assert!(marker.exists());
    info("recorded").record();

    // Off mid-run: a crash could no longer be told apart from a clean stop.
    uninstall();
    assert!(!enabled());
    assert!(!marker.exists());
    info("after uninstall").record();
    drop(book);

    // Back on mid-run: the rest of the run is watched again.
    install(dir.path(), Options::default()).unwrap();
    let book = current().unwrap();
    assert!(marker.exists());
    engine_stopped(Stop::Requested("test"));
    assert!(!marker.exists());
    uninstall();
    let kinds: Vec<String> = all(&book, SystemTime::now())
        .iter()
        .filter(|e| e.kind.starts_with("engine.") || e.kind.starts_with("test."))
        .map(|e| format!("{} {}", e.kind, e.message))
        .collect();
    assert_eq!(kinds.len(), 3, "{kinds:?}");
    assert!(
        kinds[0].starts_with("engine.stop Stopped after "),
        "{kinds:?}"
    );
    assert_eq!(kinds[1], "test.info recorded");
    assert!(kinds[2].starts_with("engine.start "), "{kinds:?}");
}
