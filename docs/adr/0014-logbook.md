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
| `config.reload` | info / warning / error | | `PUT /configs` committed (counts, `connectionsClosed`; warning when `force` pushed past errors), or was rejected |
| `config.change` | info | group or subscription | An API edit: subscription added or removed, proxy group created, changed or deleted, rules replaced, changed, deleted or moved |
| `subscription.update` | info / error | subscription | Fetched and merged with a change to the config (counting the subscription's own proxies, groups and rules), the first success after a failure, or the fetch, rebuild or commit failed |
| `proxy-provider.update` | info / error | provider | A payload replaced an earlier one (`proxies`, with the previous count), the first success after a failure, or a fetch or parse failure |
| `rule-provider.update` | info / error | provider | The rule count changed, the first success after a failure, or a load, fetch or parse failure (a provider registered empty is recorded once committed) |
| `geodata.update` | info / error | `GeoIP MMDB`, `ASN MMDB`, `geosite` | Downloaded and loaded into the rules, or the download or reload failed |
| `listener.start` | error | listener (`tun` for TUN) | A listener did not start |
| `network.interface` | info | | Outbound sockets were bound to another interface, or no longer are |
| `group.health` | info / warning / error | group | A health-check sweep found a different set of dead members: some down (warning, up to 20 names in `down`), all down (error), all up again (info). A member is dead from its first failed probe until it passes two sweeps in a row |
| `group.switch` | info | group | A `url-test` or `fallback` group routes to another member than after the previous sweep (`from`, `to`) |

Routine successes are not recorded: a first provider load belongs to the
start or config change that declared it, an unchanged refetch is noise, and
a sweep that finds the same dead members as the last one says nothing new;
a member that flaps between sweeps stays dead until it passes two in a row,
so it is one entry rather than one per sweep. Whether a success ends a
failure is read from the logbook itself (`logbook::failing`): the subject's
latest entry of the kind is an error. A recovery is then recorded even when
the provider object that failed was rebuilt by a config commit, or the
engine restarted in between.

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

`<home>/logbook/` holds two JSON Lines segments, `logbook.jsonl` and the
rotated `logbook.1.jsonl`, each at most half of the 2 MiB cap. Each line is
a whole entry. A folded entry is appended again with the same `id` and a
higher `rev`, at most once a minute (pending folds are written on flush,
when the entry leaves memory, and at drop), and on load the line with the
highest `rev` wins.

When the current segment reaches half the cap, the writer **compacts**:
both segments are rewritten into the rotated one, keeping each entry's
latest line (a failure folded every minute for a day is one line again,
not 1440) and the newest entries that fit in half the cap, minus the ones
past the 7 days; the current segment then starts empty. The entry with the
highest `id` is kept even when expired, so ids keep increasing. An open
that finds expired entries compacts as well, so a quiet logbook that never
fills a segment still drops them. Expired entries are never served, from
memory or the files.

- **No fsync.** A killed process loses nothing the kernel already has; a
  power cut loses at most the last seconds. A torn last line is skipped,
  and ended with a newline before the next append so the next line is not
  lost with it.
- **Recording never waits on the disk.** Lines go to a bounded queue
  (1024) that a writer thread drains; a full queue drops the line and warns
  once.
- **Revisions are time-based** (`max(rev + 1, unix millis)`), so they keep
  increasing across restarts even when a crash lost the last writes, and a
  client polling with `since` never misses an entry.
- **One process per directory**: `logbook.lock` is taken with
  `File::try_lock`.
- **Unclean exits**: `run.json` (`started`, `version`) is written once the
  engine is up (`engine_started`) and removed when it stops. A marker left
  behind at the next start is the `engine.unclean-exit` entry. It is not
  written earlier because a signal that arrives before `meow` installs its
  handler kills the process: a `systemctl restart` during a slow start
  would read as a crash. Turning the logbook off mid-run removes the
  marker, so it does not report a false unclean exit.

The last 256 entries stay in memory; queries past them read the files.

JSON Lines over SQLite: no new dependency or binary-size cost (ADR-0007),
appends are cheap, a torn write is one skipped line, and the files are
readable with `tail`. The size cap bounds the load at open.

### API

- `GET /logbook?limit=&before=&since=&level=&kind=&subject=`: entries
  newest first, `{"enabled", "entries", "rev", "more"}`. `limit` defaults to
  100, at most 1000. `level` is the lowest level returned; `kind` is a kind
  or its area (`config` matches `config.reload`, not `configs.x`). Page back
  with `before=<id>` of the last entry while `more` is true; poll with
  `since=<rev>` of the previous page. A bad `level` is a 400. With the
  logbook off, `enabled` is false and `entries` is empty.
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
closes the logbook and keeps its files. `meow -t` never opens it.

### Embedders

`meow_common::logbook::apply(enable)` opens or closes the logbook under the
resolved home dir, `engine_started(config)` (once the engine is up) and
`engine_stopped(Stop)` mark the run. Until `apply` runs, config commits do
not open a logbook, so tests and benches that build an `AppState` never
write into the real home. `install(dir, options)` opens one at an explicit
directory.

## Consequences

- One more writer thread and up to 2 MiB under `<home>/logbook/`.
- Producers call `event(...).record()`, which does nothing when no logbook
  is installed: no cost for headless embedders and tests.
- Messages are English sentences. Clients that localize key off `kind`,
  `level` and `fields`, which are the stable contract; message wording may
  change.

## Follow-ups

- Dial-stage tracking for `dialer-proxy` chains, so a member that times out
  for the chained server shows up as aggregated failure and stall events
  rather than one entry per connection.
- Logbook pages in meow-android and meow-ios, which call `apply`,
  `engine_started` and `engine_stopped` from their FFI.
