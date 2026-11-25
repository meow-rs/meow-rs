# PATCHES — madeye/anytls-rs → meow-anytls

Ordered list of every deviation from the pinned upstream commit
(`madeye/anytls-rs @ e6134889d3abbfaa2cb7439969dbda2ef6930611` — the fork
commit that adds `Stream::close()`; see `README.md` and `UPSTREAM`). To
refresh the vendor: copy `src/` from the new upstream commit, then
re-apply the divergences below. Sites are marked in-source with a
`(meow-rs …)` comment rather than `PATCH(n)` tags (meow-wireguard
style); this file is the replay inventory those markers point at.

```
D1 — Stream::close() is the vendoring reason itself
  The fork pin exists because upstream crates.io `anytls-rs` has no
  `Stream::close()`; meow-proxy's adapter calls it (issue #201 item 4 /
  #262). A refresh must land on a fork commit that still carries it —
  do not rebase onto upstream `anytls-rs` proper.
  Files: src/session/stream.rs (and the trait surface it hangs off)

D2 — TLS outsourced to the caller (issue #641)
  `util/cert_reloader.rs` is inert: meow-rs wires TLS through
  `meow-transport`'s `TlsLayer`, so the vendored cert-reload machinery
  is compiled but never driven. Keep the module verbatim; callers pass
  their own `TlsConnect`.
  Files: src/util/cert_reloader.rs

D3 — Server-side UDP proxy is documented dead code (issue #625)
  `src/server/udp_proxy.rs` and the UDP-over-TCP server path have no
  production callers — meow-rs does not run the vendored server. The
  in-source notes explain why it stays (cheap verbatim surface for
  future parity work); do not delete it on refresh.

D4 — Session pool lifecycle hardening (issues #201, #535, #695)
  - `session_pool.rs`: pooled sessions carry a generation stamp;
    `reset_sessions()` bumps it so in-flight dials from an older
    generation are never pooled (the #201 FD-leak root cause; #695's
    network-change reset).
  - `client.rs` stream open: a new stream no longer waits for the
    server SYNACK before returning (issue #535) — it is handed out
    right after the destination address like anytls-go/sing-anytls;
    an error SYNACK still kills the stream and the 3 s session
    watchdog still applies.
  Files: src/client/session_pool.rs, src/client/client.rs

D5 — Pluggable dialers (meow-rs `dialer-proxy`)
  - `util/socket_protect.rs`: the pre-existing global `TcpDialer`
    hook (`set_tcp_dialer`/`connect_tcp_addr`, used by Android socket
    protection and `connect_tcp_host`) is joined by a per-client
    `TransportDialer` trait returning `Box<dyn SyncStream>` —
    the dialer owns a raw chained stream; TLS stays inside the
    client's own `TlsConnect` path so SNI/ALPN/verify are identical
    to direct dials.
  - `util/tls.rs`: `SyncStream` (`AsyncStream + Sync`) is the boxed
    transport unit; `TlsConnect::connect_stream` is a new method with
    a fail-loud default — the only implementation today is
    `meow-proxy`'s `MeowTlsConnect`.
  - `client.rs`: `Client` gains `transport_dialer:
    Option<Arc<dyn TransportDialer>>` plus `set_transport_dialer`;
    `create_new_session` dials through it when present and merges
    back into `session_over_transport`, so chained sessions pool,
    reuse and reset exactly like direct ones. `connect_over`
    (`create_proxy_stream_on_tls`) is untouched and remains unpooled.
  Files: src/util/socket_protect.rs, src/util/tls.rs,
         src/util/mod.rs (exports), src/client/client.rs
  Caller contract (meow-proxy `anytls_adapter.rs`): a front-dial
  failure fails the session loudly — the dialer never silently
  falls back to a direct connection.

D6 — Certificate-time formatting uses workspace `time` (RUSTSEC-2026-0543)
  Upstream formats certificate validity timestamps through chrono, which is
  unmaintained. meow-rs removes that dependency edge rather than carrying an
  advisory exception:
  - `Cargo.toml`: the optional cert-analysis dependency is the workspace
    `time` crate and the `server` feature enables `dep:time`; do not restore
    `chrono` when replaying upstream manifest changes.
  - `src/util/cert_analyzer.rs`: `format_system_time` is rewritten around
    `::time::OffsetDateTime::from_unix_timestamp` and manual UTC formatting.
    The leading `::` is required because the x509-parser prelude glob-imports
    that crate's own `time` module, which shadows the external crate in
    type-namespace path resolution; never shorten the path when replaying.
    Returning "Invalid time" outside X.509's four-digit year range is
    intentional and enforced independently of `time/large-dates` — do not
    reintroduce upstream's epoch fallback, which would display a false date.
  - The same test module carries the migration boundary coverage (epoch,
    midnight/year boundaries, leap years, subsecond truncation, and the
    year-9999/10000 cutoff).
  Files: Cargo.toml, src/util/cert_analyzer.rs
```

Invariants every refresh must keep:

- `Client::new` / `with_pool_config` stay source-compatible for
  call-sites that never inject (the field defaults to `None`).
- `transport_dialer = None` takes the original
  `connect_tcp_addr` → `connect` path bit-for-bit.
- A pooled session is never shared across transport classes: the
  field is fixed per client before its first dial.
