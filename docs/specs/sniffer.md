# Spec: TLS/HTTP sniffer

Status: Approved rev 2.1 (architect 2026-04-11, six editorial fixes folded in)
Owner: pm
Tracks roadmap item: **M1.F-2**
Related gap-analysis row: `sniffer` (top-level config block, §5).

## Motivation

Clash Meta supports a `sniffer:` block that extracts the destination host
from the first bytes of a connection — TLS SNI for `https://`, `Host:`
header for plaintext `http://`. This lets rule matching work on
port-only flows where the client hands the listener an IP literal (common
for browsers that resolved DNS locally, for transparent-proxy traffic,
and for SOCKS5 clients that pass `dst_ip` instead of `dst_host`).

Today, meow-rs sniffs SNI only inside `tproxy/mod.rs`, only on port
443, only when `enable_sni` is true. The mixed / HTTP / SOCKS5 listeners
never sniff, so IP-literal traffic through them skips domain rules
entirely. Users hit this as "my `DOMAIN-SUFFIX` rule doesn't match even
though the browser is clearly going to `example.com`".

Upstream exposes a config block that:
- Gates sniffing globally (`enable`).
- Picks which sniffer runs per destination port (`sniff.TLS.ports`,
  `sniff.HTTP.ports`).
- Skips sniffing for explicitly-listed domains (`skip-domain`).
- Forces sniffing past the "already has a host" fast-path for domains that
  would otherwise bypass (`force-domain`).
- Decides whether a sniffed host overrides an existing hostname
  (`override-destination`) or is only used when `host` is an IP literal
  (`parse-pure-ip`).

This spec wires all of that into meow-rs with one shared sniffer
module and one call-site per inbound.

## Scope

In scope:

1. **Pure parsers live in `crates/meow-common/src/sniffer/`** — no async,
   no `TcpStream`, no trie. Just:
   - `pub fn sniff_tls(buf: &[u8]) -> Option<String>` (SNI)
   - `pub fn sniff_http(buf: &[u8]) -> Option<String>` (`Host:` header)

   **Runtime glue lives in `crates/meow-listener/src/sniffer.rs`** — the
   async entry point that listeners call, plus the compiled trie state:
   - `pub struct SnifferRuntime { cfg, skip, force }`
   - `pub async fn SnifferRuntime::sniff(&TcpStream, &mut Metadata) -> Result<...>`

   This split (pure-in-common, runtime-in-listener) matches the CLAUDE.md
   convention that `meow-common` holds trait contracts + types, not
   `TcpStream::peek` glue. It also lets pure parser tests run against
   `&[u8]` fixtures in `meow-common/tests/` while runtime integration
   tests bind real sockets under `meow-listener/tests/`.
2. Move the existing TLS parser out of `meow-listener/src/tproxy/sni.rs`
   into `meow-common/src/sniffer/tls.rs`. Tproxy keeps a one-line
   call-site against `SnifferRuntime` (which lives in the same crate).
3. New `SnifferConfig` struct in `meow-config` matching the upstream
   YAML schema (see §User-facing config).
4. Wire `SnifferRuntime::sniff` into the Mixed, HTTP, SOCKS5, and TProxy
   inbound dispatch paths. TProxy keeps its existing fallback chain
   (sniff → DNS-snoop reverse lookup → IP literal).
5. Populate `Metadata.sniff_host` on success. `Metadata::rule_host()`
   already prefers `sniff_host` over `host`, so the rule engine needs no
   change.
6. Honour `override-destination`: when `true`, also overwrite
   `Metadata.host` (not just `sniff_host`) so outbound handshakes for
   protocols like Trojan use the sniffed domain as their SNI too. When
   `false`, leave `host` alone.
7. Honour `parse-pure-ip`: when `true` (default), sniffing only activates
   for flows whose `host` is empty or an IP literal. When `false`, sniff
   every eligible flow regardless.
8. Honour `skip-domain` and `force-domain` domain lists (glob-style, same
   matcher used by `DOMAIN-KEYWORD`).

Out of scope (defer):

- QUIC / HTTP/3 sniffing (upstream has a `QUIC` sniffer; we skip until
  QUIC ever gets a listener on our side).
- `tls-fingerprint`-based sniffer bypass for detected probe traffic.
- A runtime toggle via REST API — `sniffer.enable` is load-time only.
- Sniffing on UDP flows (upstream reserves `sniff.QUIC` for this; out of
  scope per bullet 1).

## Non-goals

- A protocol-detection state machine that guesses TLS-vs-HTTP from the
  first byte. We dispatch on destination port — same as upstream — not
  payload content. Rationale: port-based is correct for >99 % of real
  traffic, robust against partial reads, and avoids the head-of-line
  latency of a "sniff everything" first-byte classifier.
- Emulating upstream's internal `dispatcher.Sniffer` goroutine layout. A
  single async function called inline by the listener is enough.
- Adding a new rule type. Sniffed host flows through `rule_host()`, which
  every existing domain rule already reads.

## User-facing config

Top-level YAML block (matches upstream exactly):

```yaml
sniffer:
  enable: true
  timeout: 100                    # milliseconds, default 100
  parse-pure-ip: true
  override-destination: false
  force-dns-mapping: false        # accepted and ignored (see divergence)
  sniff:
    TLS:
      ports: [443, 8443]
    HTTP:
      ports: [80, 8080, 8880]
  force-domain:
    - +.netflix.com
  skip-domain:
    - Mijia Cloud
    - +.push.apple.com
```

Field semantics (ordered by spec impact, not alphabetically):

| Field | Type | Default | Meaning |
|-------|------|---------|---------|
| `enable` | bool | `false` | Master switch. When `false`, all sniffing is skipped regardless of other fields. |
| `timeout` | integer (ms) | `100` | Hard cap on the initial `peek()` call. A client that connects and sends nothing within this window causes the sniffer to return empty-handed; the listener proceeds with the unsniffed flow. Bounds silent-client DoS — without this, every silent TCP connection pins a listener task indefinitely in `peek`. Range: 1–60000. |
| `sniff` | map | empty | Which protocol to sniff per port. Only `TLS` and `HTTP` are supported. Unknown keys warn and are ignored. Empty `sniff` map with `enable: true` is a config error (400 equivalent at parse time). |
| `parse-pure-ip` | bool | `true` | When `true`, sniffer runs only if `Metadata.host` is empty or parses as an `IpAddr`. When `false`, runs unconditionally. |
| `override-destination` | bool | `false` | When `true`, a successful sniff overwrites `Metadata.host` in addition to `sniff_host`. Affects outbound TLS SNI / HTTP Host rewrites. See **Trojan cert-validation gotcha** below. |
| `force-domain` | list<glob> | empty | Domains in this list bypass `parse-pure-ip`'s "skip if already a hostname" short-circuit. Useful for domains whose Happy-Eyeballs DNS resolved locally but you still want routed by the *real* SNI seen on the wire. |
| `skip-domain` | list<glob> | empty | Domains in this list are never sniffed even if eligible. Applied *after* extraction — if the sniffed SNI matches a `skip-domain` entry, the result is discarded and `sniff_host` is left empty. |
| `force-dns-mapping` | bool | `false` | **Accepted and ignored.** Upstream uses it to reuse fake-ip reverse mappings when sniffing. meow-rs implements fake-ip, but the sniffer never consults its reverse table — `TunnelInner::pre_handle_metadata` already rewrites fake IPs back to their hostnames after sniffing, before the dial — so the flag is inert; parser warns once on `true` and proceeds. Divergence documented here so config compat stays. |

Glob matcher: reuse `meow-trie::DomainTrie` for `skip-domain` and
`force-domain`. The existing trie already handles `+.example.com`,
`*.example.com`, and literal matches. No new matcher code.

### Sniffed-name adoption priority

A sniffed name is adopted into `Metadata.sniff_host` only when the flow
has no routing name of its own — `Metadata.host` empty or an IP literal.
When `host` already carries an explicit domain authority (a CONNECT
target, an absolute-form URI authority, a SOCKS5 domain), that authority
wins and the sniff is discarded: rule matching reads `sniff_host` while
the dial uses `host`, so adopting a conflicting name would route by one
host yet dial the other — `GET http://evil.com/` + `Host: good.example`
would miss `DOMAIN,evil.com,REJECT` and still dial evil.com.

Two opt-ins beat that priority. `override-destination: true` rewrites
`host` itself with the sniffed name, keeping rules and dial consistent,
and stays unconditional. And a `force-domain` entry matching
`metadata.host` adopts the sniffed name into `sniff_host` even against a
domain authority — that is exactly what the list is for: "route this
authority by the name on the wire" (a CDN front whose real SNI the
authority hides). `force-domain` therefore still does something under
`override-destination: false`: rules see the sniffed name, the dial
keeps the authority — the CDN-front contract.

### Trojan cert-validation gotcha (documented loudly)

With `override-destination: false` (the default, matching upstream), a
successful sniff only populates `Metadata.sniff_host` for rule matching
and leaves `Metadata.host` unchanged. Outbound adapters read `host` for
their own TLS SNI — so for an IP-literal destination, Trojan will hand
the peer an IP-literal SNI (or none), which typically causes peer
certificate validation failure unless the server cert is explicitly
valid for that IP or `skip-cert-verify: true` is set on the proxy.

**Most users who turn sniffing on also want `override-destination: true`.**
We match upstream's `false` default to preserve config compatibility,
but this gotcha is the #1 "why is Trojan broken after I enabled the
sniffer" support question on the upstream tracker. If your YAML has
`sniffer.enable: true` and any Trojan outbound, set
`override-destination: true` unless you have a specific reason not to.

### Deprecated alias: `experimental.sniff-tls-sni` / listener `enable-sni`

Pre-spec, tproxy listeners accepted a bespoke `enable-sni` knob that
hard-coded port-443 SNI extraction. Post-spec, that knob becomes a
deprecated alias for `sniffer.enable` (plus an implicit
`sniff: { TLS: { ports: [443] } }`). Parser emits a single warn-once at
load time:

> `enable-sni` is deprecated; migrate to the top-level `sniffer:` block.
> Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this
> release. Will be removed in a future version.

One-release migration window. Same pattern as `force-dns-mapping`: accept
and warn rather than break configs on upgrade.

### Divergences from upstream

**Divergence rule** (durable guidance for future spec authors, per
architect 2026-04-11): upstream fields that, if silently ignored, would
cause a **security or evasion gap** — e.g., a user assumes uTLS
fingerprint spoofing is active when it isn't — are rejected at parse
time with a hard error. Upstream fields whose absence only means a
*less-optimal code path* — e.g., `force-dns-mapping` is inert because
the sniffer never consults the fake-ip reverse table — are accepted
with a warn. The user's
traffic still routes correctly; they just get a log entry telling them
why the field is inert. Apply this rule whenever deciding between
warn-and-ignore vs hard-error on an unimplemented upstream knob.

1. **`force-dns-mapping` accepted-and-ignored.** Upstream uses this to
   patch back fake-ip reverse lookups into the sniff result. meow-rs
   implements fake-ip (re-added in PR #64), but the sniffer has nothing
   to patch back: `TunnelInner::pre_handle_metadata` rewrites fake IPs to
   their hostnames downstream of sniffing, before rule matching and the
   dial — so the reverse table is applied regardless of the sniff result.
   Parser emits a single `tracing::warn!` at load time and continues.
2. **No `QUIC` sniffer.** Upstream ships one; we do not. Parser warns
   and ignores `sniff.QUIC.ports` if present.
3. **No `tls-fingerprint` key.** Upstream has an undocumented feature
   gate that meow-rs does not implement. Rejected at parse time with
   a clear error (not silent) so users don't assume it's active.

## Internal design sketch

### Module layout (split across two crates)

```
crates/meow-common/src/sniffer/
├── mod.rs          // pub use {sniff_tls, sniff_http}; no async, no TcpStream
├── tls.rs          // sniff_tls(&[u8]) -> Option<String>
└── http.rs         // sniff_http(&[u8]) -> Option<String>

crates/meow-listener/src/sniffer.rs
// SnifferRuntime::sniff, timeout wrap, DomainTrie state
```

`meow-common` gets only pure parsing functions. No `tokio`, no
`TcpStream`, no `DomainTrie` — CLAUDE.md reserves `meow-common` for
trait contracts and types, not inbound dispatch glue. The runtime
(`SnifferRuntime`) lives in `meow-listener` alongside the other
`Arc<AppState>`-held structs the listeners already depend on, so
there's no round-trip through common for state that only listeners
read.

Testability split: pure parsers get byte-fixture unit tests under
`meow-common/tests/`. Runtime + timeout + trie behaviour get
integration tests under `meow-listener/tests/` binding real sockets.

### Entry point

```rust
pub struct SnifferRuntime {
    cfg: SnifferConfig,
    skip: DomainTrie,   // compiled skip-domain
    force: DomainTrie,  // compiled force-domain
}

impl SnifferRuntime {
    pub async fn sniff(
        &self,
        stream: &TcpStream,
        metadata: &mut Metadata,
    ) {
        if !self.cfg.enable {
            return;
        }
        // 1. parse-pure-ip gate
        if self.cfg.parse_pure_ip
            && !metadata.host.is_empty()
            && metadata.host.parse::<IpAddr>().is_err()
            && !self.force.contains(&metadata.host)
        {
            return;
        }
        // 2. per-port dispatch
        let Some(proto) = self.cfg.proto_for_port(metadata.dst_port) else {
            return;
        };
        // 3. bounded peek up to 8 KiB, with timeout
        let mut buf = [0u8; 8192];
        let n = match tokio::time::timeout(
            self.cfg.timeout,
            stream.peek(&mut buf),
        ).await {
            Ok(Ok(n)) => n,
            // Peek completed with IO error or timed out — swallow,
            // listener proceeds with unsniffed flow. Criterion #9/#11.
            Ok(Err(_)) | Err(_) => return,
        };
        let sniffed = match proto {
            Proto::Tls  => sniff_tls(&buf[..n]),
            Proto::Http => sniff_http(&buf[..n]),
        };
        // 4. skip-domain filter
        if let Some(host) = sniffed {
            if self.skip.contains(&host) {
                return;
            }
            metadata.sniff_host = host.clone();
            if self.cfg.override_destination {
                metadata.host = host;
            }
        }
    }
}
```

**Why 8 KiB and not 4 KiB**: real-world HTTP/1.1 requests with large
cookie jars and custom headers routinely exceed 4 KiB before the
`Host:` header. `httparse::Partial` lets us return as soon as Host is
visible, so the extra 4 KiB only matters when the client is *sending*
a header block that big — in which case 4 KiB would have missed and
8 KiB catches it. Stack-allocated, one-time per connection, negligible
cost.

**Why 100 ms default timeout**: a silent client must not pin a listener
task forever on `peek()`. Without this wrap, N concurrent silent clients
= N pinned tasks with no drain path, since `peek` waits on a zero-byte
receive window indefinitely. 100 ms is tight enough that legitimate
mobile / LTE clients occasionally miss the window (they can bump via
`sniffer.timeout`) but loose enough that sub-ms LAN probes always fit.
Matches upstream's default (engineer: grep `dispatcher/sniffer/dispatcher.go`
for the constant before implementing to confirm the exact value).

### HTTP `Host:` parser

Minimal and strict — we don't need full HTTP parsing, just the host
header on the first request of a plaintext HTTP stream:

```rust
pub fn sniff_http(buf: &[u8]) -> Option<String> {
    // Reject if not a printable ASCII method + space + path prefix.
    // Use `httparse::Request::parse`.
    let mut headers = [httparse::EMPTY_HEADER; 32];
    let mut req = httparse::Request::new(&mut headers);
    match req.parse(buf).ok()? {
        httparse::Status::Complete(_) | httparse::Status::Partial => {}
    }
    for h in req.headers.iter() {
        if h.name.eq_ignore_ascii_case("host") {
            let s = std::str::from_utf8(h.value).ok()?.trim();
            // Strip optional `:port` suffix while preserving bracketed IPv6.
            // RFC 7230 §5.4: `Host = uri-host [":" port]` where `uri-host`
            // may be an `IP-literal` in `[...]`. Naive `split(':')` would
            // mangle `[::1]:8080` → `"["`. qa case B7 locks this in.
            let host = if let Some(rest) = s.strip_prefix('[') {
                let end = rest.find(']')?;
                &rest[..end] // inner IPv6 literal, no brackets
            } else {
                s.split(':').next()?
            };
            if host.is_empty() { return None; }
            return Some(host.to_string());
        }
    }
    None
}
```

`httparse::Partial` is treated as success for our purposes — the parser
only needs to have seen the `Host:` line, not the full request. The
8 KiB peek buffer covers every real-world request's first header block
including cookie-heavy sites. If the header is past the 8 KiB window we
return `None` and the rule engine falls back to the IP literal, same as
today.

**`httparse` dependency**: add `httparse = "1"` (default-features off,
it's no-std-compatible) explicitly to `meow-common/Cargo.toml`. Do
**not** rely on transitive availability through axum — Cargo enforces
crate-visibility and `meow-common` cannot `use httparse` without its
own dep line. This is a 2-line Cargo.toml change, non-negotiable.

### Listener integration points

Exactly four call sites. Each is a single line before the existing
tunnel dispatch:

1. `crates/meow-listener/src/mixed.rs` — after peeking HTTP vs SOCKS,
   before metadata dispatch.
2. `crates/meow-listener/src/http_proxy.rs` — after parsing the
   `CONNECT` target, before tunnel dispatch.
3. `crates/meow-listener/src/socks5.rs` — after parsing the SOCKS5
   target, before tunnel dispatch.
4. `crates/meow-listener/src/tproxy/mod.rs` — replace the existing
   port-443-hardcoded SNI path with `runtime.sniff(...)`. Keep the
   DNS-snoop reverse-lookup fallback on the `sniff_host` being empty.

The `SnifferRuntime` is built once at startup (parsed from config) and
stored inside `Arc<AppState>` alongside `tunnel`. All four listeners
already hold `AppState` / `Tunnel` references.

### Interaction with existing tproxy SNI path

`tproxy/sni.rs::extract_sni` gets deleted; its test module moves to
`meow-common/src/sniffer/tls.rs`. The tproxy call site changes from:

```rust
let mut hostname = if enable_sni && orig_dst.port() == 443 {
    sni::extract_sni(&stream).await.unwrap_or_default()
} else {
    String::new()
};
```

to:

```rust
runtime.sniff(&stream, &mut metadata).await.ok();
let mut hostname = metadata.sniff_host.clone();
```

The DNS-snoop reverse-lookup fallback (the block after this in the
current file) is preserved unchanged — it runs iff `hostname.is_empty()`
after the sniffer pass.

### Error surface

`SnifferRuntime::sniff` has signature
`pub async fn sniff(&self, stream: &TcpStream, metadata: &mut Metadata)`
— **no `Result`, no error enum**. Every failure mode (peek IO error,
peek timeout, parse failure, skip-domain discard) collapses to a silent
no-op that leaves `metadata` unchanged, per the "sniffer never fails a
connection" promise (acceptance criterion #9). There is no
`SnifferError` type.

Rationale: once blockers 1 (timeout → `Ok(())`) and 2 (module split)
landed, nothing inside `sniff()` actually returns `Err`. A result type
would be dead weight and would force every call site to write
`.ok();` or `.unwrap();` for no benefit. YAGNI.

If a future extension needs to surface an error (e.g., config-error at
construction time), that error lives on `SnifferRuntime::new(...)`, not
on `sniff()`, and construction errors are load-time not
per-connection.

### Config parser

`meow-config/src/lib.rs` grows a `SnifferConfig` struct and a
`sniffer:` top-level field. The runtime compiles `skip-domain` and
`force-domain` into `DomainTrie` at load, and builds a
`HashMap<u16, Proto>` for the port dispatch. An empty `sniff` map with
`enable: true` is a parse error; an absent `sniffer:` block parses as
`enable: false`. `timeout` is parsed as `Duration::from_millis(...)`
with range 1–60000; out-of-range is a parse error.

The deprecated-alias path (see §User-facing config): if the parsed
`Config.listeners.*` or `Config.experimental` block carries an
`enable-sni` or `sniff-tls-sni` field and `sniffer` is absent, the
parser synthesises a default `SnifferConfig { enable: true, timeout:
100ms, sniff: { TLS: [443] }, ..default }` and emits the warn-once
from §User-facing config. If both are present, `sniffer:` wins and the
alias is ignored with a second warn-once.

### Observability

One `tracing::debug!("sniffer: {} → {}", metadata, host)` line on every
successful sniff. One `tracing::warn!` once at startup for each
accepted-and-ignored field. No new metrics — sniff success rate can be
derived from existing per-connection logs.

## Acceptance criteria

A PR implementing this spec must:

1. `crates/meow-common/src/sniffer/` exists with `tls.rs` + `http.rs` +
   `mod.rs`. `tproxy/sni.rs` is deleted.
2. `SnifferConfig` parses the YAML block above, including all eight
   fields: `enable`, `timeout`, `parse-pure-ip`, `override-destination`,
   `force-dns-mapping`, `sniff`, `force-domain`, `skip-domain`.
   `force-dns-mapping: true` emits exactly one warn line.
3. All four listeners (Mixed, HTTP, SOCKS5, TProxy) call `runtime.sniff`
   before tunnel dispatch. Verified by grep in review — no inbound
   reaches the rule engine without passing the sniffer pass-through.
4. A `DOMAIN-SUFFIX,example.com` rule matches a SOCKS5 flow whose client
   hands us `dst_ip=93.184.216.34, dst_port=443` and whose first record
   is a TLS ClientHello with SNI `example.com`. Integration test
   required.
5. Same rule matches an HTTP flow whose client sends
   `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n` on port 80 through
   the SOCKS5 inbound. Integration test required.
6. `override-destination: true` causes the Trojan outbound's TLS SNI to
   be the sniffed host, not the original IP literal. Integration test
   using the existing trojan mock server.
7. A domain in `skip-domain` is sniffable at the parser level but
   `metadata.sniff_host` is empty after the runtime pass. Unit test.
8. A domain already in `Metadata.host` and not in `force-domain` is
   *not* sniffed when `parse-pure-ip: true`. Unit test — verify we never
   call `stream.peek()` in that path.
9. A peek IO error does not propagate: `runtime.sniff` returns `Ok(())`
   after logging `tracing::warn!`. Unit test using a closed stream.
10. Sniffer never blocks the listener path for longer than
    `sniffer.timeout` (default 100 ms). Verified by criterion #11.
11. Sniffer peek is bounded by `sniffer.timeout`. A client that
    connects and sends nothing within the window causes
    `runtime.sniff(...)` to return with an empty `sniff_host` in
    **≤ `sniffer.timeout + 50 ms`** wall time (slack tracks whatever
    timeout value engineer adopts after the upstream-constant grep, so
    swapping 100 → 300 ms does not break the test). Asserted by a test
    that holds the client half silent for `sniffer.timeout * 5` and
    measures wall time of the sniff call, using either real time with
    the slack above or `tokio::time::pause()` + advanced clock.
12. Deprecated-alias path: a YAML file that sets the old
    `enable-sni: true` on a tproxy listener (without a top-level
    `sniffer:` block) parses as the synthesised default and emits
    exactly one warn-once. Asserted by a tracing-capture test.
13. Partial ClientHello: a peek that returns only the TLS record
    header (5 bytes) followed by a truncated handshake does not panic
    and returns `None` from `sniff_tls`. Verified by a migrated or
    newly-added test in `meow-common/src/sniffer/tls.rs`.

## Test plan (starting point — qa owns final shape)

Apply the divergence-comment convention from
`feedback_spec_divergence_comments.md` to any bullet that tests an
upstream-compat divergence; the first three bullets below show the
format.

**Unit (`crates/meow-common/src/sniffer/tls.rs`):** keep the existing
seven parse-level tests from `tproxy/sni.rs` verbatim after the move,
**plus** one new case if none of the seven already covers it:

- `sniff_tls_partial_record_header_only` — feed the parser a 5-byte
  TLS record header with no handshake body. Assert `None`, not a
  panic or index-out-of-bounds. Before merging the move, engineer
  must confirm whether `test_no_sni_on_truncated` in the current
  `tproxy/sni.rs` already covers this exact shape (it tests
  "truncate mid-extensions" which is further along); if not, add
  this bullet as a new test. Upstream: `transport/sniff/tls.go`
  tolerates short reads; we match. NOT a panic path — TLS
  ClientHellos legally span segments and a regression here would
  be silent for users on slow links.

**Unit (`crates/meow-common/src/sniffer/http.rs`):**

- `sniff_http_basic_host_header` — `GET / HTTP/1.1\r\nHost: example.com\r\n\r\n`
  → `Some("example.com")`.
- `sniff_http_host_with_port_stripped` — `Host: example.com:8080` →
  `Some("example.com")`.
- `sniff_http_case_insensitive_header_name` — `HOST: example.com` →
  `Some("example.com")`.
- `sniff_http_partial_request_ok` — only the request line and `Host:`
  header arrived; no `\r\n\r\n` yet. Assert `Some("example.com")`.
  Upstream: dispatcher/sniffer/sniff.go::HTTPSniffer returns the host as
  soon as the header is visible. We match.
- `sniff_http_binary_garbage_none` — random bytes → `None`.
- `sniff_http_no_host_header_none` — valid HTTP/1.0 request without
  `Host:` → `None`.

**Unit (`crates/meow-listener/src/sniffer.rs`):** runtime behaviour
tests live alongside the runtime, not in `meow-common`.

- `sniffer_disabled_noop` — `enable: false`, verify no `peek()` call.
- `sniffer_parse_pure_ip_skips_domain` — `host = "example.com"`,
  `parse-pure-ip: true`, not in `force-domain`. Assert zero peeks.
- `sniffer_force_domain_overrides_pure_ip` — same, but
  `force-domain: [+.example.com]`. Assert one peek, sniff_host populated.
- `sniffer_skip_domain_discards_result` — sniffer extracts
  `ads.example.com`, `skip-domain: [+.example.com]`. Assert
  `metadata.sniff_host == ""`.
- `sniffer_override_destination_mutates_host` — sniffer extracts
  `example.com`, `override-destination: true`, initial
  `host = "93.184.216.34"`. Assert `metadata.host == "example.com"` after.
- `sniffer_port_dispatch_selects_tls_vs_http` — 443 → TLS parser,
  80 → HTTP parser, 22 → no-op. Table test.
- `sniffer_peek_io_error_and_timeout_are_swallowed` — two sub-cases
  in one test: (a) stream returns `Err(ECONNRESET)` from peek, (b)
  stream is a silent client and the configured timeout fires. Both
  paths assert metadata is unchanged. Uses `tokio::time::pause()` +
  `advance` to deterministically trigger the timeout without a real
  sleep.
- `sniffer_timeout_wall_time_bounded` — with real (not paused) time,
  measure `Instant::now()` around `runtime.sniff(...)` on a silent
  client. Assert `elapsed < cfg.timeout + Duration::from_millis(50)`
  (slack tracks whatever `sniffer.timeout` the config carries — do
  not hardcode 150 ms). Guards criterion #11's wall-time requirement
  against regressions that would accidentally serialise peeks behind
  another await.
- `sniffer_force_dns_mapping_true_emits_one_warn` — use a
  tracing-capture layer. Upstream: dispatcher/sniffer reuses fake-ip
  reverse mappings here. In meow-rs the sniffer never consults the
  fake-ip reverse table (the tunnel rewrites fake IPs to hostnames
  before sniffing); accept-and-warn is the documented divergence.

**Unit (`crates/meow-config/tests/config_test.rs`):** config-parser
tests for the synthesis and validation paths — these are load-time
behaviour, not runtime.

- `parse_sniffer_deprecated_alias_emits_one_warn` — load a YAML
  fixture that sets the old `enable-sni: true` on a tproxy listener
  without a top-level `sniffer:` block. Capture tracing output via a
  `MakeWriter` test layer. Assert exactly one warn line containing
  `enable-sni` and `deprecated`, and assert the synthesised
  `SnifferConfig` has `enable: true`, `timeout = 100ms`,
  `sniff.TLS.ports = [443]`. Upstream: no equivalent — this is our own
  migration path for the pre-spec tproxy knob.
  NOT a security-relevant warn (the user's intent is preserved); just
  a migration nudge.
- `parse_sniffer_empty_sniff_map_with_enable_true_errors` — YAML with
  `sniffer: { enable: true, sniff: {} }` is rejected at parse time
  with a clear error citing the empty-map condition.
- `parse_sniffer_timeout_out_of_range_errors` — `timeout: 0` and
  `timeout: 60001` both rejected with a range error.

**Integration (`crates/meow-listener/tests/sniffer_integration.rs`,
new file):**

- `socks5_ip_literal_with_tls_clienthello_matches_domain_rule` — spin
  up a SOCKS5 listener with `sniffer.enable: true`, connect a test
  client that hands `dst_ip=127.0.0.1, dst_port=443` and writes a TLS
  ClientHello with SNI `example.com`. Install a `DOMAIN-SUFFIX,example.com
  ,REJECT` rule. Assert the connection is rejected, not proxied via the
  `MATCH,DIRECT` fallback.
- `http_proxy_connect_with_host_header_matches_domain_rule` — same, via
  the HTTP listener with a plaintext `GET / HTTP/1.1\r\nHost: example.com`
  on port 80.
- `tproxy_sniff_then_dns_snoop_fallback_order` — sniffer returns empty
  (peek sees HTTPS record but extracts no SNI because ClientHello is
  malformed); assert DNS-snoop reverse lookup still runs and populates
  `hostname`. Verifies the fallback chain.
- `trojan_outbound_uses_sniffed_sni_when_override_destination_true` —
  end-to-end: trojan mock server records the SNI it received; assert it
  matches the sniffed domain, not the IP literal the client supplied.

Granularity: ~14 starter bullets, same shape as the api-delay test plan.

## Implementation checklist (for engineer handoff)

- [ ] Create pure parsers in
      `crates/meow-common/src/sniffer/{mod.rs,tls.rs,http.rs}`. No
      async, no `TcpStream`, no trie.
- [ ] Create runtime in `crates/meow-listener/src/sniffer.rs`
      (`SnifferRuntime::sniff`, trie state, timeout wrap). Signature
      is `async fn sniff(&self, &TcpStream, &mut Metadata)` — no
      `Result` return; every failure mode collapses to a silent
      no-op (§Error surface).
- [ ] Delete `crates/meow-listener/src/tproxy/sni.rs`, move tests to
      `meow-common/src/sniffer/tls.rs`. Verify at least one migrated
      test covers a peek that returns < full ClientHello; add one if
      not.
- [ ] Add `httparse = "1"` (default-features off) to
      `meow-common/Cargo.toml` explicitly. Do not rely on transitive.
- [ ] Add `SnifferConfig` to `meow-config` with all seven fields
      (including `timeout`). Implement the `enable-sni` deprecated-alias
      path with warn-once.
- [ ] Grep `dispatcher/sniffer/dispatcher.go` for upstream's default
      peek timeout and confirm 100 ms matches. If it diverges, adopt
      upstream's value and update the spec.
- [ ] Build `SnifferRuntime` once in `meow-app/src/main.rs` and stash
      it in `AppState`.
- [ ] Wire `runtime.sniff(...)` into Mixed, HTTP, SOCKS5, TProxy
      listeners (four one-liners). TProxy's DNS-snoop reverse-lookup
      fallback is preserved after the sniffer pass.
- [ ] Add the unit + integration tests listed above.
- [ ] Update `docs/roadmap.md` M1.F-2 row with the merged PR link.
- [ ] Document the upstream divergences in
      `docs/migration-from-go-mihomo.md` once M1.H-3 lands (TODO to PM,
      not blocking this PR).
