# Config validation

meow-rs parses a mihomo/Clash Meta `config.yaml` into typed structs, then
validates and builds the runtime config. This page documents how config
defects are classified and reported.

## Defect classes (ADR-0002)

Per [ADR-0002](adr/0002-upstream-divergence-policy.md), config defects
fall into two classes:

- **Class A — hard error.** The config cannot mean what the operator
  asked for (a malformed value, an unreachable reference, a duplicated
  name). The load fails with a named error. `strict: true` additionally
  promotes *operator-authored* defects — bad `proxies:`/`proxy-groups:`/
  `rules:` entries, provider definitions, `file:`/`inline:` payloads —
  from warn-and-skip to hard errors. Remote payload bytes stay
  warn-and-skip so a third-party feed cannot veto the daemon.
- **Class B — warn and ignore.** The config asks for something meow-rs
  does not implement or honor, but the load can proceed meaningfully.
  These surface as `WARN` log lines, never errors — a verbatim mihomo
  config keeps loading.

## Unknown keys

Any key the typed schema does not model is a Class B defect (issue
#974): it warns once per rebuild pass instead of being silently dropped.
This covers every surface — the top-level config, `dns:` (including
`fallback-filter`/`nftset`), `tun:`, `sniffer:` (and each
`sniff.<PROTO>` block), `geodata:`/`geodata.url`, `geox-url:`,
`logbook:`, `traffic-ledger:`, `listeners:` entries, `proxies:` entries,
`proxy-groups:`, `proxy-providers:`/`rule-providers:` definitions (and
provider `health-check:`), and `subscriptions:` entries.

Warnings are classified into three shapes:

- **Unrecognized** — the key is not known anywhere:
  `unknown keys in top-level config: tcp-idl-timeout (not recognized; check spelling or see https://github.com/madeye/meow-rs/issues/974)`.
  A known misspelling names the correct key inline, e.g.
  `test-timeout (not recognized; mihomo uses 'timeout' (not modeled here))`.
- **Unsupported** — mihomo supports the key but meow-rs does not:
  `unsupported key in top-level config: ntp (issue #974) — NTP time sync not implemented`.
  Every `brutal-*` key lands here (open-ended experimental surface).
- **Misplaced** — the key is real but honored only on another surface:
  `misplaced key in proxy-group 'g': tfo (belongs on a proxies: entry (per-node dialer option))`.

Rules:

- Unrecognized keys aggregate, sorted, into one line per context;
  unsupported and misplaced keys warn one line each (their hints differ).
- Each warning carries context: `proxy 'name'`, `proxy 'n' (from
  provider 'p')`, `proxy-group 'g'`, `listener 'l'`, `proxy-provider 'p'`,
  `rule-provider 'r'`, `subscription 's'`, or the section name.
- `proxies:` entries are validated against a per-`type` known-key
  inventory, so protocol aliases that are accepted (`smux`/`mux`,
  `wireguard`/`WireGuard`, per-node dialer options, `dialer-proxy`)
  never warn.
- Keys that are *consumed* for a named error or a bespoke warn —
  e.g. `certificate` on hysteria2 (hard error), top-level `firewall`
  (its own misuse warn), `type: wireguard` listener/peer extras (their
  own per-field warns) — do not also emit the generic line.
- Caller-chosen key-spaces are not validated: `hosts:` names,
  `sub-rules:` block names, `nameserver-policy:` domain patterns,
  `sniff:` protocol names, provider `header:` maps.
- `dns.response-rules[]` keeps `deny_unknown_fields` — a hard error by
  design.
- `strict: true` does not promote unknown-key warnings to errors.
- Warnings re-emit on every config rebuild — `meow -t`, startup load,
  and `PUT`/`PATCH /configs` — for keys in the document itself.
  Provider-node warns fire only at provider ingest/refresh: a provider
  reused without re-parse does not re-warn on rebuild, while an
  ECH-deferred re-ingest can emit a node's warns twice.

## Save round-trip

Unknown keys are captured in `#[serde(flatten)]` `extra` maps that
serialize back, so `save_raw_config`, `POST /api/config/save`, and the
`PUT /configs` persistence write them to disk verbatim (sorted by key) —
a config saved through the API keeps the keys it warned on, ready for
when a later build learns to honor them.
