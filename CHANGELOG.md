# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Changed

- **BoringSSL is now the only crypto library; rustls is gone from the runtime.**
  Two changes land together. First, every TLS handshake moved off rustls onto
  BoringSSL (`meow_transport::tls::TlsLayer`): proxy handshakes (Trojan, VLESS,
  VMess, HTTP/SOCKS5-over-TLS, SS plugins, ECH tunnel, AnyTLS), URL-test health
  probes, DoT/DoH upstreams, and every internal HTTP(S) fetch (`reqwest`
  removed; the in-tree client gained direct dialing through the host
  resolver/`SocketProtector` hooks, custom headers, and a Content-Length
  precheck). Second, the **Hysteria2 outbound was ported from quinn (rustls) to
  quiche**, Cloudflare's BoringSSL-native QUIC + HTTP/3 stack, using quiche's
  `boringssl-boring-crate` feature so it links the SAME vendored BoringSSL as
  the TLS layer. rustls, tokio-rustls, quinn, h3, h3-quinn, reqwest,
  and webpki-roots are no longer runtime dependencies; rustls remains only as a
  dev-dependency for the loopback TLS test servers.
  **Build change:** `boring`, `tokio-boring` and `boring-sys` move together
  through the workspace table (5.2 as of #572; quiche 0.30 accepts
  `boring >=4.19,<6`) so that quiche and meow-transport share one
  `links = "boringssl"` copy; `boring-sys` (cmake + a C++ compiler) is a hard
  build requirement on every target. The `boring-tls`/`ech` features are
  no-op aliases. The Hysteria2 quiche client is a single driver task that
  bridges quiche's synchronous state machine to the async `DuplexStream` (TCP)
  and `UdpSession` (UDP datagrams) with real QUIC-flow-control backpressure;
  Salamander obfs and port-hopping are applied on the driver's own UDP socket.
  Observable runtime differences: BoringSSL's default ClientHello replaces
  rustls' for proxies without `client-fingerprint`; TLS session resumption is
  per BoringSSL `SSL_CTX` (64-entry cache); the QUIC ClientHello is now quiche's.

- **boring/tokio-boring 4.22 → 5.2 and quiche 0.29 → 0.30.** quiche 0.30
  accepts `boring >=4.19,<6`, which unblocks the 5.x line the workspace had
  been waiting on. One observable difference, from the newer vendored
  BoringSSL: the *default* ClientHello — every handshake without a
  `client-fingerprint`, including DoT/DoH and the Hysteria2 QUIC handshake —
  now advertises a post-quantum key share (`X25519MLKEM768`), which makes it
  about 1.2 KiB larger and can split the QUIC Initial across two packets
  (verified against Hysteria 2.9.2). Named fingerprint profiles pin their
  curve list explicitly, so their ClientHello and the JA3 pins in
  `boring_tls_test` are unchanged. The 4.x-era `TolerantFlushStream` flush
  workaround is removed (see the #569 entry under Fixed). (#572)

- **`ipv6` is now effective end-to-end and keeps the `false` default.** The
  `ipv6` flag previously only gated a handful of code paths — the resolver
  queried A and AAAA regardless — so the documented `false` default and
  `GET /configs` disagreed with the actual runtime behaviour. The flag now
  drives the whole resolution pipeline: with `ipv6: false` (the default,
  matching mihomo/Clash) AAAA lookups are skipped and the resolver answers
  IPv4-only; with `ipv6: true` dual-stack domains are queried for both A and
  AAAA (concurrently, with IPv4 tried first as a connection fallback) and
  `DirectAdapter` can fall back to IPv6 when IPv4 connectivity fails. The
  default literal is now centralized in `meow_config::effective_ipv6`
  (previously scattered across six `unwrap_or(...)` sites), and the parser,
  `GET /configs`, and `website/guide/configuration.md` all agree on `false`.
  **Operators who relied on the old always-dual-stack behaviour of an
  omitted `ipv6` key must now set `ipv6: true` explicitly.**

- DNS dual-stack resolution (`resolve_ips` / `lookup_ip_with_ipv6_inner`) now
  queries A and AAAA **concurrently** when IPv6 is enabled, collecting both
  address families with IPv4 ordered first. `DirectAdapter::dial_tcp` iterates
  the full address list, so an IPv4 connect failure no longer discards the IPv6
  candidate — IPv6 remains a connection fallback.

### Fixed

- **Provider-sourced group members are now health-checked** (#543 item 1,
  #555). The periodic sweep and `GET /group/{name}/delay` resolved
  `group.members()` names through the route table, where `use:` /
  `include-all` provider members are not keys, so a `use:`-only
  `url-test` / `fallback` group woke every interval to probe nothing,
  never became `alive`, and the delay endpoint returned `{}` for it. The
  `Proxy` trait gains `member_proxies()`, which every group implements
  over its static members *and* provider slots; both callers probe
  through it. Load-balance still drops its `use:` slots at parse
  (#555 item 3) and providers have no scheduled check of their own yet.

- **`RULE-SET` rules now see refreshed rule-provider content without a
  config rebuild** (#553). The rule parser received a snapshot `Arc` of
  each provider's set, so a periodic refresh or `PUT /providers/rules/{name}`
  logged "refreshed: N rules" and bumped `updated_at` while live traffic
  kept matching the startup payload until the next `PUT /configs` or
  restart. `RuleProvider` now implements `RuleSet` by reading through its
  lock, and the parser map (`rule_provider::live_ruleset_map`, replacing
  `snapshot_ruleset_map`) hands rules the provider itself; the DNS
  `nameserver-policy` `rule-set:` matcher reads through the same way
  instead of cloning a snapshot per query. Providers rebuilt by a config
  reload still bypass the API registry (#543 item 2).

- **HTTP/2 transports (gRPC, h2, xhttp) and the h2mux multiplexer now
  advertise 4 MiB per-stream / 16 MiB per-connection receive windows.**
  Every client handshake used h2's defaults, so the download direction of a
  gRPC / h2 / xhttp / h2mux stream stalled every 64 KiB waiting for a
  WINDOW_UPDATE round-trip — a throughput ceiling of roughly 64 KiB per RTT
  (#495 item 12). The windows now match Go's `http2.Transport` defaults,
  which is what mihomo's gun / h2 clients and sing-mux's h2mux client
  advertise; the upload direction is unchanged (bounded by the server's
  window). Per-stream memory stays bounded by the 4 MiB window because
  every read still releases capacity chunk by chunk.

- **Built-in dashboard Overview loads with live traffic streaming.** Consume
  `/traffic` through one reconnecting WebSocket instead of waiting for an
  endless HTTP JSON response. Mode, listeners, and connections load
  independently; changing the API secret refreshes authentication. Add
  dashboard browser and lifecycle regression tests to CI.

- **Relay groups can now terminate on real protocol adapters, not just
  `http`/`socks5`/`snell`.** Every hop after the first runs
  `ProxyAdapter::connect_over`, which previously only `direct`, `reject`,
  `http`, `socks5`, and `snell` implemented — a `relay` chain ending on a
  `vless`/`vmess`/`trojan`/`anytls`/`ss` node failed at hop 1 with
  `connect_over not supported`. `connect_over` now means the adapter's full
  post-connect pipeline over the passed stream — its own TLS/WS/obfs stack
  to its own server, then the protocol handshake (mihomo
  `DialContextWithDialer` semantics) — and is implemented by `vless`,
  `vmess`, `trojan`, `shadowsocks`, and `anytls` on top of the existing
  five. Two latent bugs surfaced and were fixed along the way:
  `http`/`socks5` `connect_over` silently skipped the adapter's own TLS
  layer, so a `tls: true` node in a non-first position sent a plaintext
  handshake to a TLS endpoint; and `RelayGroup::connect_over` did not
  resolve group members, so a nested relay holding a selector hit
  `NotSupported` on the group instead of running the selected leaf.
  Nested `relay` groups are now *flattened* into the outer chain at any
  position — the preceding hop dials the inner chain's entry point
  (previously a group member at a non-first position yielded `""`/`0`
  target metadata for the preceding hop). A `dialer-proxy` member whose
  inner outbound is itself a `relay` group is spliced the same way — the
  enclosing chain already defines the path, so the per-outbound dialer is
  not applied again. Expansion deeper than 16 fails the dial outright
  rather than retaining an unexpanded group mid-chain (config resolution
  already guarantees the group graph is acyclic; the bound stops
  pathological hand-built graphs). Hops with an empty
  `addr()` (REJECT, unresolvable groups) are skipped for metadata but
  still run their own `connect_over` so failures stay correctly
  attributed. Boundaries: `hysteria2` stays first-hop-only (QUIC cannot ride a TCP
  stream), `ss` with an external SIP003 plugin fails loudly (the subprocess
  owns its outbound leg), and mux pooling is bypassed on relay hops because
  a relay-supplied stream is single-use. The same fix makes `dialer-proxy`
  work for `anytls`, which previously fell back to the relay wrapper and
  still failed. (#570)

- **TLS handshakes no longer fail on multiplexed transports whose
  `poll_flush` pends.** Every TLS-over-mux handshake — AnyTLS, smux, and any
  stream whose `poll_flush` waits on a writer-task acknowledgement — died at
  the first `BIO_flush` with the misleading "TLS handshake failed operation
  would block". tokio-boring's BIO bridge turns `Poll::Pending` into
  `ErrorKind::WouldBlock`, and boring 4.22.0's `BIO_CTRL_FLUSH` handler stored
  the error but never called `BIO_set_retry_write`, so `SSL_get_error` mapped
  a routine retry to fatal `SSL_ERROR_SYSCALL`. Upstream fixed this in
  cloudflare/boring@ed76885, which only the 5.x line ships: #571 first
  carried an in-tree wrapper that reported a pending flush as complete, and
  #572 replaced it with the upstream fix by moving the workspace to boring
  5.2 (quiche 0.30 lifted the `boring < 5` constraint). HTTPS
  URL-test probes over AnyTLS/smux recover (visible symptom: url-test groups
  with `https://` URLs reported nearly all mux members dead while the same
  nodes carried real traffic fine). Regression test:
  `d1_tls_handshake_over_pending_flush_stream`. (#569, #571, #572)

- **Provider `header:` maps now accept mihomo's list form, and rule-providers
  honor `header:` at all.** mihomo types provider headers as
  `map[string][]string`, but meow-rs typed `proxy-providers` `header` as
  `map[string]string`, so a mihomo-style config failed to load with
  `invalid type: sequence, expected a string`; rule providers had no
  `header` key and silently ignored one. Both provider kinds now accept the
  list form (single-string values keep working for meow-rs-legacy configs)
  and send multi-value headers as repeated field lines (RFC 9110 §5.2; meow
  emits every list value, whereas Go's HTTP/1.1 writer special-cases
  `User-Agent` to its first value). Headers apply to rule-provider initial
  load, prefetch, and periodic refresh, and to proxy-provider load (a
  proxy-provider `interval` is parsed but not scheduled, so those providers
  have no periodic refresh yet). A user-supplied `User-Agent` replaces the
  built-in default instead of duplicating it, and reserved/framing header
  names (`Host`, `Connection`, `Content-Length`, `Accept-Encoding`, and the
  rest of the hop-by-hop set) are dropped at emission rather than written,
  mirroring Go `net/http`'s `reqWriteExcludeHeader` — a second `Host:` or
  `Content-Length:` line is a request-smuggling primitive
  (mihomo parity: `component/http/http.go`). Header field names and values
  are validated per RFC 9110 (token-only names, CTL-free values) rather
  than only checking CR/LF/colon, so padded names like `Host ` / ` Host` /
  `Host\t` — which could dodge the reserved-name match and be normalized by
  tolerant intermediaries into a duplicate `Host:` line — are now rejected
  instead of emitted. Note: non-string header values
  (e.g. `header: {X: 123}`) were previously coerced to `"123"` on API-pushed
  configs and are now rejected, matching mihomo.

- **`load-balance` groups are now health-checked, so `url`, `interval`, and
  `lazy` take effect.** A `load-balance` group accepted these fields but never
  ran a health check, so it could keep routing to a dead member. It now joins
  the same periodic sweep as `url-test`/`fallback`: members are probed every
  `interval` seconds (default 300; `0` disables the sweep) against `url`
  (default `https://www.gstatic.com/generate_204`), and `lazy: true` defers
  probing until the group next carries traffic. Two known divergences from
  mihomo remain and are tracked in #555: `lazy` still defaults to `false`
  (upstream `true`, shared with `url-test`/`fallback`), and `select`/`relay`
  members are still not swept. A `load-balance` group with `use:` or
  `include-all` now logs a warning that provider members are ignored; a
  provider-only group still parses but ends up with no members, so the
  warning is the signal to look for. See #485.

- Proxy groups declared before their nested groups now retain those forward
  references even when either group also names a missing proxy.

- **Shadowsocks AEAD-2022 UDP now interoperates in both directions**
  (#566). Both the inbound listener and the outbound adapter previously ran
  with an all-zero `UdpSocketControlData`: inbound replies echoed
  `client_session_id = 0` with a zero server session ID (strict clients like
  sing-box reject them), and every outbound datagram repeated
  `client_session_id = 0`/`packet_id = 0`, so a conforming ssserver's replay
  filter dropped everything after the first packet. Inbound relay sessions
  are now keyed by `client_session_id` (SIP022 §3.2.4, matching ssserver's
  `NatKey::SessionId`) with a random non-zero server session ID, a
  session-wide reply packet counter shared across flows, and a per-session
  client packet-ID replay window; outbound associations mint a random client
  session ID, count packet IDs up, and filter replies through
  per-server-session windows. The inbound session table shares the
  listener's `max-connections` bound and retains each session for the spec's
  60-second minimum measured from its last datagram, independent of flow
  liveness; both packet-ID counters are checked (32-bit targets terminate
  the association rather than wrapping), and the outbound reply tracker
  evicts single least-recently-used windows instead of clearing the table.
  Reply headers now carry the responder's real socket address, and malformed
  reply datagrams are dropped per-packet instead of killing the association.

- Hysteria2 authentication no longer advertises HTTP/3 datagrams, preventing
  the server's HTTP/3 receiver from consuming raw QUIC UDP relay packets.
  The TProxy test image now includes the mandatory BoringSSL build toolchain.
- Internal HTTP downloads strip authentication and cookie headers when a
  redirect changes origin, and reject bodies that do not match Content-Length
  before replacing provider caches.
- Hysteria2 bounds queued TCP writes by bytes, retries exhausted QUIC stream
  limits without discarding requests, and propagates terminal stream errors.
  Restored idle keepalive and the remote response wait for `fast-open: false`;
  cancelling authentication or dropping a client releases its driver socket.
- **Auto-created `GLOBAL` selectors now default to the config's primary
  outbound.** Global mode always dispatches through `GLOBAL`, but the implicit
  selector previously sorted every registry key and used the first one when no
  choice was stored. That made global mode silently select `DIRECT` or route
  through an alphabetically-first quota/expiry pseudo-node. The generated
  selector still lists every proxy for mihomo-compatible dashboards, while its
  first member is now the final valid `MATCH` target, falling back to the first
  declared group or leaf proxy. Explicit user-defined `GLOBAL` groups remain
  unchanged.
- **AnyTLS UDP no longer deadlocks against sing-box/mihomo inbounds**
  (#535). sing-box reads the udp-over-tcp request before reporting handshake
  success, so the stream SYNACK is gated on the request arriving — while the
  client waited for SYNACK first and only sent the request lazily with the
  first datagram, leaving both sides waiting until the dial timed out. The
  UoT request is now flushed on the stream-open path, ahead of the SYNACK
  wait (`Client::create_proxy_stream_with_payload`); ordinary TCP streams
  and the vendored server's unconditional-SYNACK shape are unchanged. The
  same ordering fix was applied to the vendored `Client::create_udp_proxy`
  for consistency.

- **`merge_family` no longer revives an expired sibling family.** When a new
  A answer merged into an entry whose AAAA had already expired, the old code
  unconditionally marked AAAA as `queried`, which `family_hit()` then read as a
  fresh `NoData`, suppressing re-resolution of AAAA. The sibling is now only
  carried forward when its own answer is still fresh; an expired sibling stays
  a `Miss` so the resolver re-queries it on demand.

- **`resolve_ips` no longer short-circuits when one family is cached.** A
  single-family cache entry (e.g. A already fresh, AAAA still `Miss`) no longer
  prevents the missing family from being queried. Only already-fresh families
  are dropped from the query set; the missing required family is always
  fetched, preserving `DirectAdapter`'s cross-family fallback.

- **`GET /configs` reports the same `ipv6` default the runtime uses.** The API
  previously reported `ipv6: false` for an unset config while the runtime
  actually queried AAAA anyway, causing UIs/controllers to display a state the
  resolver ignored. Both sides now share `meow_config::effective_ipv6` and
  default to `false` — and the reported value is the one actually enforced.

- **A fast NXDOMAIN no longer suppresses a slow positive answer.** Within a
  single nameserver tier, the first definitive negative (NODATA/NXDOMAIN) is
  now held for a short grace period while the remaining upstreams keep racing;
  a positive answer arriving later always wins. This restores correct
  behaviour for split-horizon / multi-upstream configurations. Network errors
  (`Err`) are not treated as definitive and never short-circuit the pool.

- **Single-flight broadcast misses no longer surface as SERVFAIL.** A
  subscriber that attached just after the publisher sent (and removed its
  inflight slot) previously received `Closed` and could be judged `Failed`.
  `lookup_real_with_ttl` now re-reads the cache on a missed broadcast, so the
  already-merged result is served instead of a transient SERVFAIL.

- **DoH response bodies are now size-capped.** `doh_exchange` previously
  `read_to_end`-ed an unbounded buffer, letting a misbehaving or hostile
  upstream drive unbounded heap growth. Responses are now rejected once they
  exceed the DNS message maximum (65535 B) plus HTTP header headroom.

- **`snapshot()` hides IPs of an expired family.** When one family is still
  fresh and the other has expired, only the fresh family's IPs appear in the
  cache snapshot panel.

- **Hosts-table AAAA answers follow the global `ipv6` switch.** An AAAA query
  for a domain present in the hosts trie is gated by `ipv6` exactly like every
  other AAAA path: with `ipv6: false` it returns NODATA even when the hosts
  file carries an IPv6 address for the domain (the entry remains reachable for
  A queries and for `ipv6: true` configs). This keeps the global toggle a
  single, predictable switch — dual-stack operators who pin addresses in
  `hosts:` must enable `ipv6: true` for the v6 entries to be served.
