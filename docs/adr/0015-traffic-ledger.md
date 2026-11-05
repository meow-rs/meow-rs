# ADR 0015: Traffic ledger, per-day traffic by host, app, policy and interface

- **Status:** Accepted
- **Date:** 2026-11-02
- **Author:** Claude (on behalf of @gengjiawen)
- **Related:** #764 (per-proxy traffic), [ADR-0014](0014-logbook.md) (logbook)

## Context

`GET /traffic` streams the current rates and `GET /statistics` (#764) sums
what each proxy carried since the engine started. Both forget everything
at a stop, so a client cannot answer "how much did I use this month",
"which sites or apps used my data yesterday" or "how much went through
this node last month". The mobile apps keep a daily total of their own,
but not by host, app or policy, and every embedder would otherwise have
to build the same table.

mihomo has no equivalent, so this is a meow extension (ADR-0002).

## Decision

### What is recorded

For every local day, per host, app, leaf policy, dialer-proxy carrier
and interface label:
bytes sent, bytes received and the number of connections opened and UDP
flows that sent something (`requests`).

- **Host** is the registrable domain (`www.example.co.uk` →
  `example.co.uk`, via the public-suffix list), lowercased; an IP address
  is kept in its canonical form. A day keeps at most `MAX_IP_HOSTS`
  (8192) distinct addresses; past it, that day's other bare-address flows
  (peer-to-peer swarms, a scan) fold into the host `*`. An address the
  day has keeps its row, and a flush with more new addresses than the
  day has room for keeps the busiest. No paths, ports or times finer than
  a day.
- **App** is the app that opened the flow: the package name an Android
  VPN supplies in `Metadata::process`; elsewhere the owner of a flow from
  this host, found with the socket lookup PROCESS-NAME rules use, named
  after its outermost `.app` bundle on macOS (a browser's helper
  processes count as the browser) and its process name on Linux and
  Windows. Empty when the platform cannot tell, and for flows from other
  hosts (a LAN gateway, a remote listener client).
- **Policy** is the leaf proxy's name, the `chains[0]` a connection
  records, by name only: a renamed node starts a new row, and no server
  fingerprint is kept.
- **Via** is, for a leaf that dials its server through a `dialer-proxy`,
  the member that carries that hop: the last pick of the front's groups,
  or the front itself. It is named as the flow is tracked, with the same
  peek its chains use, so a flow over a pooled or multiplexed session (a
  Snell pool) has one too; a UDP flow's is named before its dial, as its
  leaf is, since the dial commits the front's pick and a round-robin front
  moves on after it. The front is asked on the network the hop takes,
  which the leaf names (`dialer_hop_network`): a Shadowsocks or SOCKS5 UDP
  flow goes to its server as datagrams and kcptun sends every flow as
  them, while UDP over TCP (Trojan, VLESS, a mux session) rides a TCP hop;
  a load-balance front picks a UDP hop among its UDP-capable members only.
  The peek predicts the dial, and a front that rotates or hashes can still
  carry the hop over another member: a flow on a session opened earlier
  (kcptun, a pool) took that session's pick; a SOCKS5 UDP flow's control
  connection takes a round-robin pick before its datagrams' hop does; and
  a consistent-hashing front hashes the relay address a SOCKS5 server
  returns, or the IP a kcptun dial (or a Shadowsocks UDP one whose front
  cannot carry a name) resolves the server to, where the peek hashed the
  server's name. Only the nearest hop is named; a front that chains on
  through a dialer of its own is not followed. Empty for every other flow.
  It counts in the policy view only: there a flow counts under its leaf
  and under its carrier, its request included, so a node's row is what it
  carried as an exit plus what it carried as a front, and the rows add up
  to more than the totals. The host, app and interface views and the
  totals count each flow once. The bytes are the flow's payload, not the
  hop's wire bytes `/statistics` counts for the member.
- **Interface** is a label the embedder pushes (`set_interface`), such as
  `Wi-Fi` or `Cellular` on mobile; empty when none was given.

Unlike the logbook, the ledger records destinations. With hosts on (the
default), it is a coarse browsing history, and with apps on, one by app.
It never leaves the device: `traffic-ledger: {enable: false}` turns it
off, `hosts: false` and `apps: false` keep an empty host or app for what
is counted from then on (by flows that opened with them on too), and
`DELETE /traffic/ledger` empties it, write-ahead log included.

### Recording

The relay path is untouched. A flow's counters (`ConnCounters`) carry a
`LedgerTag` — its host, app, leaf name and carrier, shared with the connection
rather than copied — while the ledger records, and nothing when it does
not; `ConnectionInfo` does not change size. A connection counts as a
request as it is tracked, a UDP flow as it first sends, so a dial that
lost the race for its NAT entry, or was flushed, is none. Its bytes reach
the ledger when the tunnel, a `traffic_ledger::Source`, settles every
live connection, headless connection and UDP flow: every 60 s, at local
midnight, before the interface label changes, at a query and at a stop. A
flow settles once more as it is closed, and once more as its last handle
drops, for bytes still in flight at the close. What a settle hands over
is counted under the interface label it read before it took the bytes,
with the ledger's epoch (see the apps section below): a label change
racing a settle leaves what came before it under the label it came on, and
a clear racing one drops what it took. A label change settles the flows
on the caller's thread and switches, without waiting for the writer: a
writer held up by the disk still files what came before under the label
it came under. A stop settles them on the caller's thread too, while the
ledger still records, and the writer writes what is pending as it stops,
however long the disk holds it. Settling is a `fetch_max`
on two atomics per flow, so racing settlers take disjoint parts. A burst
of flows to distinct hosts (a scan) asks the writer for a flush early, at
4096 pending rows, so pending counts stay bounded in memory.

UDP flows have no connection entry, so a UDP flow the ledger files gets
counters of its own, kept in a table the settle walks until the flow's
outbound is dropped.

The app lookup stays off the flow's path. The platform lookup can scan
every process (macOS walks each process's sockets), so a flow from this
host is tracked and dialed at once, and one `meow-app-lookup` thread
looks its owner up in turn and hands the counters the app. Until then
the flow settles nothing: its counters keep its bytes and its request,
and settle as the app is known. The lookup holds a handle to the
counters, so a flow that closes first still files everything under its
app. A burst of flows costs one core at most; past 1024 queued lookups,
a flow is filed under no app. The lookup runs only while the ledger
records with apps on, on platforms with a socket lookup (Linux, macOS,
Windows), for flows from a loopback address, and for flows through the
TUN device or a transparent listener (redir, tproxy) whose source
address is one of this host's: the host's own traffic, not a LAN
client's, which costs no scan. Linux reads the interface addresses
(again on a miss after a second, and on a hit after ten, as an address
the host gave up may be a LAN client's now), as a bind there takes any
address with `ip_nonlocal_bind` set, which some gateways set; macOS and
Windows bind to the address. A dual-stack listener sees an IPv4 client as
`::ffff:a.b.c.d`; it is looked up under the IPv4 address, in the IPv4
socket table and then the IPv6 one, which lists an AF_INET6 socket on an
IPv4 address (Java's default) under the mapped address. PROCESS-NAME,
PROCESS-PATH and UID rules share the lookup. An Android VPN supplies the package with
every flow and needs none. A flow whose rules looked its process up
already is looked up again: rule matching keeps its enriched metadata to
itself, so `/connections` stays as it was.

A flow whose app is being looked up as the ledger crosses a boundary
files what it carried until then once its app is known. A clear, and a
ledger installed while none recorded, drop everything counted so far:
they move the ledger's epoch on, and a flow that settles under a newer
epoch than its last settle drops what it carried until then and the
request it had not counted, as the drop could not settle it. Midnight
and a change of interface label do not wait for the lookups: such a
flow's bytes until then go under the day and label of when its app is
known, a lookup's delay later. No platform has both a lookup and an
interface label today.

### Days

A day is a local calendar day, numbered from 1970-01-01. The embedder
pushes the UTC offset and its next change (`set_time_zone`) before it
starts the engine and whenever it changes, so a phone that crosses a DST
change or a time zone files traffic under the day the user sees; what was
counted under the previous zone is written under its day first. The day
is decided as the writer takes what is pending, so a writer held up past
the change's 5 s wait files that under the new zone's day; this takes a
change of zone that moves the date while the disk stalls. Without one,
meow uses UTC. A flush up to two minutes past midnight files what is
pending under the day that ended; a later one, after the clock jumped (a
resume from sleep, a clock set at boot), under today. Retention is 62
days, today included, which always covers last month in full. Older days
are deleted at a flush. Months are not compacted.

### Storage

`<home>/traffic/traffic.db`, SQLite in WAL mode (the logbook's bundled
SQLite, iOS/tvOS linking the system library), one table:

```sql
CREATE TABLE traffic (
    day INTEGER NOT NULL, host TEXT NOT NULL, app TEXT NOT NULL,
    policy TEXT NOT NULL, via TEXT NOT NULL, interface TEXT NOT NULL,
    upload INTEGER NOT NULL, download INTEGER NOT NULL,
    requests INTEGER NOT NULL,
    PRIMARY KEY (day, host, app, policy, via, interface)
) WITHOUT ROWID;
```

A flush is one transaction of `INSERT … ON CONFLICT DO UPDATE` that adds
to the existing row, so any grouping and drill-down is a `SUM … GROUP BY`
over a span of days. A writer thread owns the connection. A lock file
keeps a second meow process off the directory, and a database that cannot
be read (or carries a schema no meow writes) is set aside and started
over, as for the logbook. One from a newer meow is left alone, neither
read nor rewritten, and the ledger stays off. `PRAGMA user_version` is
the schema version (3); readers in other processes
(`traffic_ledger::read`, used by the Android UI process) rely on it.
Schema 1, without `app`, was only written by test builds before the
ledger shipped and is set aside like a damaged one. Schema 2, without
`via`, was written by builds of `main` before it; the writer moves it on
in place as the ledger opens (its rows keep an empty `via`), and a reader
in another process reads it as it is until then.

### API

`GET /traffic/ledger?from=&to=&by=&host=&app=&policy=&interface=` returns
the traffic of the local days `from` to `to` (`YYYY-MM-DD`, both
included, today by default; `from` after `to` is a 400), grouped `by`
`host` (the default), `app`, `policy` or `interface`, rows largest first,
plus the totals, each flow counted once. A row also gives `via_upload`,
`via_download` and `via_requests`: the part of a policy row the node
carried as a dialer-proxy front, zero in the other views. `host`, `app`,
`policy` and `interface` narrow it to one group, for drill-down;
`policy` to the flows that policy's row counts, those it was the leaf of
and those it carried the hop of, so drilling into a node by policy shows
the outbounds that chained through it. There is no `via` grouping or
filter of its own. A query settles the live flows first and writes
them, so it is current; when the write fails (a full disk), it is a 503,
and what was pending is kept for the next flush. Off, or in a `minimal`
build, it answers `enabled: false` with no rows. `DELETE /traffic/ledger`
deletes everything, from the database on disk too while the ledger is
off; a failure is a 503. That includes a reader in another process
holding the deleted traffic on disk past the busy timeout (1 s): the
write-ahead log cannot be checkpointed and truncated under it, so the
clear says so, and a later one finishes it. What was pending is dropped
either way, as the clear asked. A clear from another process
(`traffic_ledger::clear_at`, which the Android UI process calls while the
engine runs in the VPN's) commits on a connection of its own. The engine's
writer sees SQLite's `data_version` move at its next write (within a
minute, or at a query) and drops what it counted until then, its backlog
and the day's addresses toward the IP cap, as a clear of its own would,
rather than write them over the clear. The process lock leaves
`clear_at` the only other connection that commits.

### Config

```yaml
traffic-ledger:
  enable: true   # default
  hosts: true    # default; false files every flow under no host
  apps: true     # default; false files every flow under no app, no lookups
```

A reload applies it, writing what was counted under the previous
options first. A batch a failing disk held for a retry is written without
the hosts or apps turned off since. Embedders call `traffic_ledger::apply`
with the profile's values; the mobile FFIs also call `set_interface` and
`set_time_zone`.

### Builds

Behind meow-common's `traffic-ledger` feature (SQLite plus `psl`), in
meow-app's `full` and not in `minimal` (ADR-0007), where a stub keeps the
API and records nothing.

## Consequences

- A client can show today, this month and last month by host, app,
  policy or interface, and drill from one into another, from a single
  table.
- With the ledger on, each connection takes the ledger's pending-counts
  mutex once as it opens, and each flow pays for two more atomics plus a
  settle a minute. `ConnCounters` grows by the tag (112 B with the app
  slot and the carrier, one allocation per flow either way). A UDP flow allocates its own
  counters, and a flow to a bare IPv6 address formats it (an allocation
  past 23 bytes). Off, a connection pays one relaxed load.
- With apps on, on Linux, macOS and Windows every flow from this host
  costs a platform socket lookup on the lookup thread: Linux serves most
  from its short-TTL caches, macOS scans every process's sockets. On
  Linux and Windows, an IPv4 socket not in the IPv4 table is looked for
  in the IPv6 one too. A
  host's own flows reach the ledger a little later than the rest, by the
  lookup queue's length, and what one carried before its app is known is
  lost if the ledger stops first. `apps: false` stops the lookups.
- The database grows with distinct hosts and apps per day: IP hosts are
  capped, registrable domains and apps are not, and days go after 62. A
  row takes about 74 B on disk, so a day at the IP cap adds about 600 KB
  and 62 of them about 36 MiB; the writer holds the day's addresses in
  memory, under 1 MB at the cap. The cap was 1024 at first, which a
  phone's apps that dial bare addresses (peer-to-peer, CDNs picked by
  address) filled within a day.
- A report lists every group: a month by host can run to the IP cap
  times its days (about 254,000 rows and 0.8 s to read on a desktop when
  every day is full of new addresses).
- The standalone `meow` sets no time zone, so its days are UTC days.
- iOS and tvOS name no app: a packet tunnel does not see a flow's owner.

## Follow-ups

- An in-app switch and per-host deletion in the mobile apps.
- `meow-cli` support.
- A row limit on reports (the largest rows and a count of the rest), so
  a month by host stays small for a phone's UI.
- The standalone `meow` reads the system time zone (UTC today).
- A cheaper macOS socket lookup (one `net.inet.tcp.pcblist_n` read
  instead of a walk of every process), which PROCESS-NAME rules would
  share.
