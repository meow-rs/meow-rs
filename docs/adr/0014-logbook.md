# ADR 0014: Logbook, a persistent record of notable engine events

- **Status:** Accepted
- **Date:** 2026-10-18
- **Author:** Claude (on behalf of @gengjiawen)
- **Related:** #768 (dialer-proxy chain health), Surge's Logbook

## Context

meow has two ways to see what the engine did, and neither keeps anything:

- `GET /logs` streams every tracing line while a client is connected. On a
  phone nobody is connected when it matters, and the lines are written for
  developers: a provider that fails every 60 seconds is 60 lines an hour
  that say the same thing.
- Connection notes (`connection-notes: true`) explain one connection, kept
  in memory for the last 256.

Questions like "why did my subscription stop updating on Tuesday", "when did
half of my `Proxy` group go down" or "did meow crash overnight" need the
events that matter, kept across restarts and crashes, readable by a client
without parsing log lines. Surge has this as the Logbook, next to its log.

mihomo has no equivalent, so this is a meow extension (ADR-0002).

## Decision

### What is recorded

Engine and proxy events only. The logbook never records the destinations of
user traffic: on a phone, a persistent list of hosts is a browsing history.
Rule edits are recorded by index, never by rule text. An error is recorded
as the engine reports it, so a rejected config's error can quote the config
line that failed to parse, as `PUT /configs` returns it. Per-connection
detail stays in connection notes.

Each entry has a dotted **kind** (`<area>.<event>`) and a **level**
(`info`, `warning`, `error`), which is also the outcome: a failed reload is
an `error` `config.reload`, not a separate kind. Kinds are never renamed
once released, because clients filter, label and translate by kind.

| Kind | Level | Subject | When |
|---|---|---|---|
| `engine.start` | info | | The engine started (`version`, `config`) |
| `engine.stop` | info / error | | A clean stop (`reason`: `SIGTERM`, `service stop`, ...) or a run that failed (`error`); `uptime` in seconds |
| `engine.unclean-exit` | warning | | Recorded at start: the previous run ended without a stop (crash, kill, power cut); `version`, `started`, `lastSeen` |
| `logbook.cleared` | info | | `DELETE /logbook` ran |
| `logbook.reset` | warning | | The database could not be read and the logbook started over (`error`); the old file is kept as `logbook.db.corrupt` and ids start again from 1 |
| `config.reload` | info / warning / error | | `PUT /configs` committed (counts, `connectionsClosed`; warning when `force` pushed past errors), or was rejected |
| `config.change` | info | group or subscription | An API edit: subscription added or removed, proxy group created, changed or deleted, rules replaced, changed, deleted or moved |
| `subscription.update` | info / error | subscription | Fetched and merged with a change to the config (counting the subscription's own proxies, groups and rules), the first success after a failure, or the fetch, rebuild or commit failed |
| `proxy-provider.update` | info / error | provider | A payload replaced an earlier one (`proxies`, with the previous count), the first success after a failure, or a definition, fetch or parse failure (a provider a lenient build left out is recorded once the build is committed) |
| `rule-provider.update` | info / error | provider | A payload changed the rule count of an earlier one, the first success after a failure, or a load, fetch or parse failure (a provider registered empty, or left out by a lenient build, is recorded once the build is committed) |
| `geodata.update` | info / error | `GeoIP MMDB`, `ASN MMDB`, `geosite` | Downloaded and loaded into the rules, or the download or reload failed |
| `listener.start` | error | listener (`tun` for TUN) | A listener did not start |
| `network.interface` | info | | The interface outbound sockets bind to (TUN `auto-route: global`) changed, or they no longer bind to one. Recorded for a binding once its TUN listener is up: a reload candidate's binding, installed for the validation's dials, records nothing until then, and nothing at all when the candidate is rejected |
| `group.switch` | info | group | A `url-test` or `fallback` group routes to another member than after the previous sweep (`from`, `to`; `reason` when `from` went down) |
| `dialer-proxy.switch` | info | chained outbound | The member of a `dialer-proxy` group carrying the outbound's chains to its server changed (`group`, `from`, `to`; `reason` when `from` is blocked for that server) |
| `dialer-proxy.check` | info / error | chained outbound | A health check of the outbound failed through every member of its `dialer-proxy` group tried (`group`, `reason`, `tried`), or passed again |

Failure reasons in these entries come from a fixed vocabulary
(`timed out`, `connection refused`, `closed before any reply`, ...), not
the error text, which can name server addresses, and members are named,
never their servers.

Routine successes are not recorded: a first provider load belongs to the
start or config change that declared it (so does the first payload of a
provider registered empty, such as a download adopted after the fetch
deadline), and an unchanged refetch is noise. Members of a group going
down are not recorded either: the same airport nodes sit in several
groups, so one dead node made an entry in each, and none of them said
whether the traffic still went where it should. Whether a success ends a
failure is read from the logbook itself (`logbook::failing`): the subject's
latest entry of the kind is an error. A recovery is then recorded even when
the provider object that failed was rebuilt by a config commit, or the
engine restarted in between.

Producers record what a running configuration does. A build that may not
be committed (startup builds its providers more than once, and a
`PUT /configs` candidate can be rejected) records nothing itself: what it
leaves for the logbook — the providers a lenient build left out
(`DroppedProviders`), a provider's load failure or recovery, a TUN
binding — is recorded by the commit that installs it. An embedder that loads a config with
`load_config` records the config's `dropped_providers` once it runs it.

### Coalescing

A producer can mark an event `coalesce()`. It then folds into the latest
entry of the same kind and subject when that entry has the same level and
last happened within an hour: the count goes up and the entry takes the
latest message and fields. Any other event of the kind for the subject in
between starts a new entry, so a failure, a success and a failure stay
three entries. A provider that fails every minute for a day is one entry
with a count of 1440; a failure more than an hour after the last starts a
new one.

### Storage

`<home>/logbook/logbook.db` is an SQLite database that one writer thread
owns. SQLite is bundled (`rusqlite` with `bundled`), so every platform runs
the same version, and any platform's SQLite bindings and tools read the
file. Schema version 1, in `PRAGMA user_version`:

```sql
CREATE TABLE entries (
    id      INTEGER PRIMARY KEY AUTOINCREMENT,
    rev     INTEGER NOT NULL,  -- write sequence, see the API
    time    INTEGER NOT NULL,  -- first occurrence, Unix milliseconds
    last    INTEGER NOT NULL,  -- latest occurrence; time until a repeat folds in
    count   INTEGER NOT NULL,
    kind    TEXT NOT NULL,
    level   TEXT NOT NULL,     -- info, warning, error
    subject TEXT NOT NULL,     -- '' when the event has none
    message TEXT NOT NULL,
    fields  TEXT               -- JSON object, NULL when none
);
CREATE INDEX entries_rev ON entries (rev);
```

A row is an entry as the API serves it (`last` is served once `count` is
above 1). The schema is a contract with readers in other processes: a
later version may add columns, indexes or tables, and raises
`user_version` only for a change an older reader cannot read. meow
neither reads nor writes a database with a higher version than it knows,
and leaves the file alone: it checks the version on a read-only
connection, so not even the write-ahead log is checkpointed.

- **Writes.** A new entry is inserted; a folded repeat updates its row in
  place (an upsert by `id`, only to a higher `rev`), at most once a minute.
  A held-back repeat is written once due (the writer wakes for it, with no
  further event needed), on flush, when its entry leaves memory, and at
  close. It gets a new `rev` when a later one was handed out meanwhile: a
  reader polling the database with `since` sees it even after later
  entries reached the disk, while one polling memory does not see an
  unchanged entry again. The writer
  drains a bounded queue (1024) and commits up to 256 operations per
  transaction. **Recording never waits on the disk**: a write the full
  queue refuses stays pending in memory like a held-back repeat, is tried
  again as soon as the writer has room, and is lost only if its entry
  leaves memory first; the first such write warns. Flush, close and
  `DELETE /logbook` first queue every pending write, waiting up to 2 s for
  room, so what they wait for includes them.
- **Failed commits.** A transaction takes the write lock up front
  (`BEGIN IMMEDIATE`). A commit that fails (a process holding the lock
  past the 1 s busy timeout, a full disk) keeps its writes, up to 1024,
  and is tried again with the next commit or after 10 s; a query that needs
  the database fails meanwhile (`GET /logbook` answers 503). A single
  entry SQLite refuses (too big, a constraint) is skipped with a warning
  instead. The delete behind `DELETE /logbook` needs no room in the
  queue: it sets a bound, and the writer deletes the rows below it, drops
  the queued writes below it, and keeps trying until the delete commits.
- **Durability.** WAL with `synchronous=NORMAL`: a committed write
  survives a killed process, and a power cut can lose the last commits but
  not the database. The write-ahead log is checkpointed every 64 pages and
  cut back to 256 KiB after a checkpoint; the page cache is 256 KiB, for
  the memory limit of an iOS network extension.
- **Bounds.** Entries last seen more than 7 days ago are deleted at open
  and then hourly. Past the 2 MiB cap (pages in use), the oldest entries
  are deleted down to three quarters of it, and `auto_vacuum=INCREMENTAL`
  hands the freed pages back to the file system. AUTOINCREMENT keeps ids
  increasing past deleted rows, after `DELETE /logbook` too. Expired
  entries are never served, from memory or the database.
- **Damage.** `PRAGMA quick_check` runs at open. A file that is not a
  database, fails the check, or holds rows meow cannot read (a text
  `count`) is renamed to `logbook.db.corrupt`
  (replacing an older one), and the logbook starts over with a
  `logbook.reset` entry. Ids then start again from 1, so a client drops
  the entries it holds.
- **Revisions are time-based** (`max(rev + 1, unix millis)`), so they keep
  increasing across restarts even when a crash lost the last writes, and a
  client polling with `since` never misses an entry.
- **One writer per directory**: `logbook.lock` is taken with
  `File::try_lock`. SQLite's own locks only order transactions; two meow
  processes would hand out the same ids.
- **Unclean exits**: `run.json` (`started`, `version`) is written once the
  engine is up (`engine_started`) and removed when it stops. A marker left
  behind at the next start is the `engine.unclean-exit` entry. It is not
  written earlier because a signal that arrives before `meow` installs its
  handler kills the process: a `systemctl restart` during a slow start
  would read as a crash. Turning the logbook off mid-run removes the
  marker, so it does not report a false unclean exit.

The last 256 entries stay in memory, so the first page, polls, coalescing
and `latest_level` never touch the disk. Queries past them run on the
writer's connection, after everything queued.

#### Readers in other processes

`logbook::read(dir, query)` opens the database read-only for one query:
for an app whose UI runs in another process than the engine, or that
shows the logbook while the engine is stopped. It does not see the
repeats the writer holds back (at most a minute). A reader in another
language reads the schema above. Every reader:

- opens the database read-only, keeps the connection short-lived and
  never leaves a transaction open: readers do not block the writer, but a
  long read keeps the write-ahead log from being checkpointed, and a
  connection that writes holds up the writer's commits;
- has write access to the directory, or to the existing `-wal` and `-shm`
  files: a read-only connection to a WAL database still writes the
  shared-memory index;
- uses one SQLite library per process for this file. Two copies in one
  process (the one bundled in meow's library and the platform's) do not
  see each other's POSIX locks, and closing a handle in one drops the
  other's locks. A process that links meow reads through `logbook::read`;
- on iOS, does not hold the database open while the app is suspended: an
  app that holds an SQLite lock in an App Group container at suspension is
  killed (`0xdead10cc`);
- on Android, opens with `SQLiteDatabase.OPEN_READONLY` and never changes
  the journal mode (`enableWriteAheadLogging`, `disableWriteAheadLogging`).

#### SQLite over JSON Lines

The first version kept two JSON Lines segments with compaction. SQLite
answers what clients ask without loading the file: a page past memory or
a filtered query reads the rows it returns (about 0.5 ms for a page of
100, release build), an open does not parse every entry, a fold updates
its row instead of appending a line that a compaction later drops, and
every platform an app runs on reads it with its own tools. The cost is
binary size: the bundled SQLite adds about 1 MiB (x86_64 release). The
`logbook` Cargo feature carries it, and the `minimal` bundle leaves it
out, since the aarch64 minimal binary has about 0.5 MiB left under its
8 MiB hard cap (ADR-0007). Built without the feature, the logbook API
stays, records nothing, and `GET /logbook` reports `enabled: false`.

### API

- `GET /logbook?limit=&before=&since=&level=&kind=&subject=`: entries
  newest first, `{"enabled", "entries", "rev", "more"}`. `limit` defaults to
  100, at most 1000. `level` is the lowest level returned; `kind` is a kind
  or its area (`config` matches `config.reload`, not `configs.x`). Page back
  with `before=<id>` of the last entry while `more` is true; poll with
  `since=<rev>` of the previous page. A bad `level` is a 400; a query
  that needs the database while it cannot answer is a 503. With the
  logbook off, or built without the `logbook` feature, `enabled` is false
  and `entries` is empty.
- `DELETE /logbook`: deletes every entry, then records `logbook.cleared`.
  Ids keep increasing.

An entry:

```json
{"id": 42, "rev": 1792316400000, "time": "2026-10-18T09:00:00Z",
 "last": "2026-10-18T09:40:00Z", "count": 3,
 "kind": "proxy-provider.update", "level": "error", "subject": "airport",
 "message": "Updating proxy provider 'airport' failed: connection timed out",
 "fields": {"error": "connection timed out"}}
```

`last`, `subject` and `fields` are omitted when empty.

### Config

```yaml
logbook:
  enable: true   # default
```

The section is read at start and on every config commit; turning it off
closes the logbook and keeps its database. `meow -t` never opens it.

### Embedders

`meow_common::logbook::apply(enable)` opens or closes the logbook under the
resolved home dir, `engine_started(config)` (once the engine is up) and
`engine_stopped(Stop)` mark the run. Until `apply` runs, config commits do
not open a logbook, so tests and benches that build an `AppState` never
write into the real home. `install(dir, options)` opens one at an explicit
directory. `query(query)` and `clear()` serve the API in the engine's
process; `read(dir, query)` serves other processes (see Storage). An
embedder that runs a config from `meow_config::load_config` calls
`config.dropped_providers.record()` once it runs it, after committing its
rule providers. An
embedder that wants the logbook enables `meow-common/logbook`; the `full`
bundle of `meow` does.

## Consequences

- One more writer thread, and up to 2 MiB under `<home>/logbook/` plus a
  write-ahead log of up to 256 KiB while the logbook is open.
- About 1 MiB of bundled SQLite in `full` builds; none in `minimal`.
- Producers call `event(...).record()`, which does nothing when no logbook
  is installed: no cost for headless embedders and tests.
- Messages are English sentences. Clients that localize key off `kind`,
  `level` and `fields`, which are the stable contract; message wording may
  change.

## Follow-ups

- Dial-stage tracking for `dialer-proxy` chains, so a member that times out
  for the chained server shows up as aggregated failure and stall events
  rather than one entry per connection.
- Logbook pages in meow-android and meow-ios, which enable
  `meow-common/logbook` and call `apply`, `engine_started`,
  `engine_stopped` and `Config::dropped_providers.record()` from their
  FFI.
