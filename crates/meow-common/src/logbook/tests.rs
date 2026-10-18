use super::store::format_uptime;
use super::*;
use std::fs;
use std::time::UNIX_EPOCH;

/// 2027-01-15T08:00:00Z.
fn t0() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_800_000_000)
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
    .entries
}

fn lines(dir: &Path) -> usize {
    fs::read_to_string(dir.join("logbook.jsonl"))
        .unwrap()
        .lines()
        .count()
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
            "rev": 1_800_000_000_123_u64,
            "time": "2027-01-15T08:00:00.123Z",
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
            event("group.switch", Level::Info, "switched").subject("rules"),
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
fn repeats_within_a_minute_reach_the_disk_once() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(failure("rules", "a"), at(0));
        book.record_at(failure("rules", "b"), at(1));
        book.record_at(failure("rules", "c"), at(2));
        assert_eq!(all(&book, at(3))[0].count, 3, "memory is current");
        book.flush();
        assert_eq!(
            lines(dir.path()),
            2,
            "the first write and the held-back repeats"
        );
    }
    let book = open(dir.path(), at(10));
    let entry = &all(&book, at(10))[0];
    assert_eq!((entry.count, entry.message.as_str()), (3, "c"));
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
fn a_torn_last_line_is_skipped() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        book.record_at(info("kept"), at(1));
    }
    let current = dir.path().join("logbook.jsonl");
    let mut bytes = fs::read(&current).unwrap();
    bytes.extend_from_slice(br#"{"id":2,"rev":2,"time":"2027-01-"#);
    fs::write(&current, bytes).unwrap();
    {
        let book = open(dir.path(), at(2));
        assert_eq!(messages(&all(&book, at(2))), ["kept"]);
        assert_eq!(book.record_at(info("next"), at(3)).id, 2);
    }
    // The torn line was ended, so the next line was not glued to it.
    let book = open(dir.path(), at(4));
    assert_eq!(messages(&all(&book, at(4))), ["next", "kept"]);
}

#[test]
fn segments_rotate_under_the_size_cap_and_keep_the_newest() {
    let dir = tempfile::tempdir().unwrap();
    let max_size = 4096;
    {
        let book = Logbook::open_at(dir.path(), small(8, max_size), t0()).unwrap();
        for i in 0..200 {
            book.record_at(info(&format!("entry {i}")), at(i));
        }
        book.flush();
    }
    let size = |name: &str| fs::metadata(dir.path().join(name)).map_or(0, |m| m.len());
    assert!(size("logbook.jsonl") + size("logbook.1.jsonl") <= max_size);
    assert!(size("logbook.1.jsonl") > 0, "rotated at least once");
    let book = Logbook::open_at(dir.path(), small(8, max_size), at(300)).unwrap();
    let entries = all(&book, at(300));
    assert_eq!(entries[0].message, "entry 199");
    assert!(entries.len() > 8, "pages back into the files");
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
fn a_compaction_folds_the_writes_of_an_entry_into_one_line() {
    let dir = tempfile::tempdir().unwrap();
    let max_size = 16 * 1024;
    {
        let book = Logbook::open_at(dir.path(), small(8, max_size), t0()).unwrap();
        book.record_at(info("the first entry"), at(0));
        // A failure retried every two minutes for two days: every repeat
        // reaches the disk, many times what the segments hold.
        for i in 0..1440 {
            book.record_at(failure("rules", "timed out"), at(1 + 120 * i));
        }
    }
    let size = |name: &str| fs::metadata(dir.path().join(name)).map_or(0, |m| m.len());
    assert!(size("logbook.jsonl") + size("logbook.1.jsonl") <= max_size);
    let now = at(1440 * 120);
    let book = Logbook::open_at(dir.path(), small(8, max_size), now).unwrap();
    let entries = all(&book, now);
    assert_eq!(messages(&entries), ["timed out", "the first entry"]);
    assert_eq!(entries[0].count, 1440);
}

#[test]
fn expired_entries_leave_the_files_but_ids_keep_increasing() {
    let dir = tempfile::tempdir().unwrap();
    {
        let book = open(dir.path(), t0());
        for i in 0..20 {
            book.record_at(info(&format!("entry {i}")), at(i));
        }
    }
    drop(open(dir.path(), at(6 * 24 * 3600)));
    assert_eq!(lines(dir.path()), 20, "still within the retention");
    let now = at(8 * 24 * 3600);
    {
        let book = open(dir.path(), now);
        assert!(all(&book, now).is_empty());
        book.flush();
    }
    let on_disk = fs::read_to_string(dir.path().join("logbook.1.jsonl")).unwrap();
    assert_eq!(on_disk.lines().count(), 1, "only the highest id is kept");
    let book = open(dir.path(), now);
    assert_eq!(
        book.record_at(info("next"), now).id,
        21,
        "ids keep increasing"
    );
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
    assert_eq!(book.latest_level("group.health", "rules"), None, "per kind");
    book.record_at(event(kind, Level::Info, "updated").subject("rules"), at(1));
    assert_eq!(book.latest_level(kind, "rules"), Some(Level::Info));
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
    assert_eq!(unclean.fields["started"], "2027-01-15T08:00:00Z");
    assert_eq!(unclean.fields["lastSeen"], "2027-01-15T08:00:50Z");
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

    let page = |query: Query| book.query_at(&query, at(20));
    let first = page(Query {
        limit: Some(3),
        ..Query::default()
    });
    assert_eq!(messages(&first.entries), ["x", "p9", "p8"]);
    assert!(first.more);
    assert_eq!(first.rev, first.entries[0].rev);

    // Paging back crosses from memory (4 entries) into the files.
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

/// The only test that touches the process-wide logbook.
#[test]
fn the_installed_logbook_records_and_watches_the_run() {
    let dir = tempfile::tempdir().unwrap();
    let marker = dir.path().join("run.json");
    info("before install").record();
    let book = install(dir.path(), Options::default()).unwrap();
    assert!(enabled());
    assert!(Arc::ptr_eq(
        &book,
        &install(dir.path(), Options::default()).unwrap()
    ));
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
    let book = install(dir.path(), Options::default()).unwrap();
    assert!(marker.exists());
    engine_stopped(Stop::Requested("test"));
    assert!(!marker.exists());
    uninstall();
    let kinds: Vec<String> = all(&book, SystemTime::now())
        .iter()
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
