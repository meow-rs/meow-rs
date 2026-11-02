# ADR 0015: Traffic ledger, per-day traffic by host, policy and interface

- **Status:** Accepted
- **Date:** 2026-11-02
- **Author:** Claude (on behalf of @gengjiawen)
- **Related:** #764 (per-proxy traffic), [ADR-0014](0014-logbook.md) (logbook)

## Context

`GET /traffic` streams the current rates and `GET /statistics` (#764) sums
what each proxy carried since the engine started. Both forget everything
at a stop, so a client cannot answer "how much did I use this month",
"which sites used my data yesterday" or "how much went through this node
last month". The mobile apps keep a daily total of their own, but not by
host or policy, and every embedder would otherwise have to build the
same table.

mihomo has no equivalent, so this is a meow extension (ADR-0002).

## Decision

### What is recorded

For every local day, per host, leaf policy and interface label:
bytes sent, bytes received and the number of connections and UDP flows
opened (`requests`).

- **Host** is the registrable domain (`www.example.co.uk` →
  `example.co.uk`, via the public-suffix list), lowercased; an IP address
  is kept as it is. A day keeps at most `MAX_IP_HOSTS` (1024) distinct
  addresses; past it, that day's other bare-address flows (peer-to-peer
  swarms, a scan) fold into the host `*`. No paths, ports or times finer
  than a day.
- **Policy** is the leaf proxy's name, the `chains[0]` a connection
  records, by name only: a renamed node starts a new row, and no server
  fingerprint is kept. A dialer-proxy front hop is not counted twice.
- **Interface** is a label the embedder pushes (`set_interface`), such as
  `Wi-Fi` or `Cellular` on mobile; empty when none was given.

Unlike the logbook, the ledger records destinations. With hosts on (the
default), it is a coarse browsing history. It never leaves the device:
`traffic-ledger: {enable: false}` turns it off, `hosts: false` keeps
policies and interfaces with an empty host, and `DELETE /traffic/ledger`
empties it.

### Recording

The relay path is untouched. A flow's counters (`ConnCounters`) carry a
`LedgerTag` — its host and leaf name, both shared with the connection
rather than copied — while the ledger records, and nothing when it does
not; `ConnectionInfo` does not change size. The connection count is added
as the flow is tracked. Its bytes reach the ledger when the tunnel, a
`traffic_ledger::Source`, settles every live connection, headless
connection and UDP flow: every 60 s, at local midnight, before the
interface label changes, at a query and at a stop. A flow settles once
more as it is closed, and once more as its last handle drops, for bytes
still in flight at the close. Settling is a `fetch_max` on two atomics per
flow, so racing settlers take disjoint parts.

UDP flows have no connection entry, so a UDP flow the ledger files gets
counters of its own, kept in a table the settle walks until the flow's
outbound is dropped.

### Days

A day is a local calendar day, numbered from 1970-01-01. The embedder
pushes the UTC offset and its next change (`set_time_zone`), so a phone
that crosses a DST change or a time zone files traffic under the day the
user sees; without one, meow uses UTC. Retention is 62 days, today
included, which always covers last month in full. Older days are deleted
at a flush. Months are not compacted.

### Storage

`<home>/traffic/traffic.db`, SQLite in WAL mode (the logbook's bundled
SQLite, iOS/tvOS linking the system library), one table:

```sql
CREATE TABLE traffic (
    day INTEGER NOT NULL, host TEXT NOT NULL, policy TEXT NOT NULL,
    interface TEXT NOT NULL, upload INTEGER NOT NULL,
    download INTEGER NOT NULL, requests INTEGER NOT NULL,
    PRIMARY KEY (day, host, policy, interface)
) WITHOUT ROWID;
```

A flush is one transaction of `INSERT … ON CONFLICT DO UPDATE` that adds
to the existing row, so any grouping and drill-down is a `SUM … GROUP BY`
over a span of days. A writer thread owns the connection. A lock file
keeps a second meow process off the directory, and a database that cannot
be read (or one from a newer schema) is set aside and started over, as
for the logbook. `PRAGMA user_version` is the schema version; readers in
other processes (`traffic_ledger::read`, used by the Android UI process)
rely on it.

### API

`GET /traffic/ledger?from=&to=&by=&host=&policy=&interface=` returns the
traffic of the local days `from` to `to` (`YYYY-MM-DD`, both included,
today by default), grouped `by` `host` (the default), `policy` or
`interface`, rows largest first, plus their sums. `host`, `policy` and
`interface` narrow it to one group, for drill-down. A query settles the
live flows first, so it is current. Off, or in a `minimal` build, it
answers `enabled: false` with no rows. `DELETE /traffic/ledger` deletes
everything.

### Config

```yaml
traffic-ledger:
  enable: true   # default
  hosts: true    # default; false keeps policies and interfaces only
```

A reload applies it. Embedders call `traffic_ledger::apply` with the
profile's values; the mobile FFIs also call `set_interface` and
`set_time_zone`.

### Builds

Behind meow-common's `traffic-ledger` feature (SQLite plus `psl`), in
meow-app's `full` and not in `minimal` (ADR-0007), where a stub keeps the
API and records nothing.

## Consequences

- A client can show today, this month and last month by host, policy or
  interface, and drill from one into another, from a single table.
- With the ledger on, each connection takes the ledger's pending-counts
  mutex once as it opens, and each flow pays for two more atomics plus a
  settle a minute. A UDP flow allocates its own counters, and a flow to a
  bare IPv6 address formats it (an allocation past 23 bytes). Off, a
  connection pays one relaxed load.
- The database grows with distinct hosts per day: bounded by the IP-host
  cap and 62 days.

## Follow-ups

- An in-app switch and per-host deletion in the mobile apps.
- `meow-cli` support.
