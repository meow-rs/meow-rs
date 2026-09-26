# Changelog

All notable changes to meow-rs are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Release notes are mirrored onto the GitHub Release for each tag; this file is
the canonical, in-repo source a release is cut from.

## [Unreleased]

### Added

- **In-process `gost-plugin` for Shadowsocks** — `plugin: gost-plugin` now
  runs natively instead of spawning a SIP003 subprocess, matching mihomo's
  built-in: TCP → optional TLS (ALPN `http/1.1`, SNI from `host` or a `Host`
  header override) → WebSocket → optional smux v1 session (`mux` defaults
  to `true` upstream; one session per connection, stream close tears it
  down). The full option surface is supported — `mode` (required,
  `websocket`), `host` (default `bing.com`), `path`, `tls`, `mux`,
  `headers`, `skip-cert-verify`, `name-cert-verify`, `fingerprint`
  (SHA-256 certificate pin — `TlsConfig::cert_pin` replaces CA
  verification, matching upstream SSL pinning), `certificate`/`private-key`
  (mTLS; inline PEM or file path — file-sourced PEMs are re-stat per dial
  and hot-reloaded on change, poll-based parity with upstream's file
  watch), and `ech-opts.enable` + `ech-opts.config` (inline
  ECHConfigList, bounded to the u16 wire limit; DNS-queried ECH is not
  supported and errors clearly). `name-cert-verify` is wired through a new
  `TlsConfig::verify_name` — the certificate is verified against it while
  the wire SNI stays `host`. Nested `plugin-opts` maps now flatten
  correctly for all plugins (`headers` → repeated `header=K:V`, other maps
  → `key.sub=value`). `mux` requires the `mux` cargo feature; builds
  without it reject `mux=true` at parse time. (#533)

- **In-process `shadow-tls` for Shadowsocks** — `plugin: shadow-tls` now
  runs natively (mihomo `transport/sing-shadowtls` parity) instead of
  spawning a SIP003 subprocess. All three protocol versions are
  supported: v1 (TLS 1.2 cover handshake then plaintext), v2 (8-byte
  HMAC-SHA1 transcript tag on the first framed record), and v3
  (ClientHello `legacy_session_id` authentication + XOR-swizzled cover
  records with embedded rolling HMACs). Options mirror upstream:
  `host` (required cover SNI), `password`, `version` (required — 1, 2
  or 3; upstream has no default),
  `alpn` (default `h2,http/1.1` — YAML list values flatten),
  `skip-cert-verify`, `name-cert-verify` (`TlsConfig::verify_name`),
  `fingerprint` (SHA-256 certificate pin), `certificate`/`private-key`
  (mTLS, PEM or path), and the node-level `client-fingerprint` uTLS
  shaping. Two deliberate divergences from upstream, both forced by
  BoringSSL lacking uTLS's `SessionIDGenerator` hook: the v3 cover
  handshake always ends in an expected transcript-mismatch failure that
  is recovered from after the shim has verified a swizzled cover record
  (TLS 1.2 covers still run real certificate verification before the
  failure; TLS 1.3 covers cannot be cert-verified at all — the post-
  ServerHello flight is undecryptable under the diverged transcript, so
  `skip-cert-verify`/`fingerprint` have no effect there), and the cover
  session is torn down quietly rather than completed. (#533)

- **In-process `restls` for Shadowsocks** — `plugin: restls` now runs
  natively (mihomo `transport/restls` parity). Because restls commits its
  BLAKE3 authentication tag into the TLS `session_id` — part of the
  handshake transcript — no generic TLS stack can speak it; the client is
  implemented at the record level in `meow-transport` (the pattern
  established by `reality_tls`), driving real TLS 1.3 *and* TLS 1.2
  handshakes with full certificate-chain, hostname, CertificateVerify and
  optional SHA-256-pin verification. After the handshake the cover's
  first encrypted record is unmasked to detect a restls relay; a plain
  cover falls back to transparent TLS automatically. Data then travels in
  script-shaped tagged records with per-direction BLAKE3 MACs and rolling
  counters (`250?100<1,350~100<1,600~100,300~200,300~100` by default).
  Options mirror upstream: `host`, `password` and `version-hint`
  (`tls12`/`tls13`) are required, `restls-script`, `skip-cert-verify`,
  `name-cert-verify` and `fingerprint` (SHA-256 certificate pin) are
  supported; the upstream `force-tls12` test knob maps to the `tls12`
  path. UDP relay is unsupported, matching upstream. (#533)

- **In-process `jls` for Shadowsocks** — `plugin: jls` now runs natively
  (mihomo `transport/jls` / `metacubex/jls-tls` parity). jls authenticates
  inside a genuine TLS 1.3 handshake: `ClientHello.random` is replaced by
  a 16-byte seed sealed with AES-256-GCM under
  `SHA-256(password ‖ authData)` / nonce `SHA-256(username ‖ authData)`,
  where `authData` is the serialized hello with `random` zeroed, and the
  server answers with the same construction in `ServerHello.random`. No
  generic TLS stack can control those fields, so the client is driven at
  the record level on the shared TLS 1.3 machinery introduced for restls.
  When the server's random authenticates, certificate-chain and
  CertificateVerify checks are skipped exactly as upstream (the
  camouflage certificate is a throwaway); when it does not, the full
  checks run against `host` — an unauthenticated jls server relays to a
  real cover, so the handshake completes and is then rejected
  (`ErrJLSAuthFailed` parity). Post-handshake traffic is plain TLS
  application records — no tagging, masking, or script — with KeyUpdate
  rotation and `close_notify` handled. Options mirror upstream: `host`,
  `username` and `password` are required, `alpn` defaults to
  `h2,http/1.1`; there is no `skip-cert-verify` because jls's
  authentication *is* the certificate check. UDP relay is unsupported,
  matching upstream. (#533)

- **In-process `kcptun` for Shadowsocks** — `plugin: kcptun` now runs
  natively (kcptun/kcp-go wire parity). The transport lives in
  `meow-transport` as a poll-driven `KcpStream` (ARQ over UDP on the
  zonyitoo `kcp` core) plus the kcp-go-compatible crypt envelope
  (`none`/`xor`/`salsa20`/CFB ciphers/`aes-128-gcm`, PBKDF2-HMAC-SHA1
  KDF), Reed-Solomon FEC with peer auto-tuning, and optional snappy
  stream compression. `meow-proxy` adds the SIP003 option parser, a
  pooled session layer (round-robin `conn` KCP sessions with lazy
  `autoexpire` reuse expiry; `scavengettl` is parsed but is a no-op —
  client-side linger does not apply) over in-tree smux v1 with
  keepalive NOPs and `frameSize`/`smuxbuf`/`streambuf` sizing, and
  upstream-compatible UDP relay: UDP datagrams travel as
  UDP-over-TCP records (`sp.udp-over-tcp.arpa:0`, length-prefixed)
  through a pooled smux stream. The KCP socket goes through
  `dial_udp_endpoint`, so `dialer-proxy` chains tunnel the datagrams
  instead of leaking raw UDP. Options mirror upstream kcptun
  (`key`/`crypt`/`mode`/`conn`/`autoexpire`/`scavengettl`/`mtu`/
  `ratelimit`/`sndwnd`/`rcvwnd`/`datashard`/`parityshard`/`dscp`/
  `nocomp`/`nodelay`/`interval`/`resend`/`nc`/`sockbuf`/`smuxver`/
  `smuxbuf`/`streambuf`/`framesize`/`keepalive`/`acknodelay`), and only
  `smuxver=1` is supported, matching our smux layer. The KCP core is a
  vendored `kcp` crate reworked to `kcp-go` v5.6.72 retransmission/Input
  semantics (immediate flush on window slide or fast-retransmit, ACK
  clocking, `acknodelay`, linear RTO backoff, FEC-aware RTT/window
  filtering). The feature is in the `full` bundle and excluded from
  `minimal` (cipher/FEC/snappy dependency weight). One operational
  note: `KcpStream` progress is poll-driven — retransmits and
  dead-link detection advance while the stream is polled, which the
  smux session reader guarantees for pooled sessions. (#533)
- **Opt-in `strict: true` config mode** — by default an entry that fails
  to parse (a `proxies:` node, a `proxy-groups:` block, a `rules:` line,
  a `proxy-providers:`/`rule-providers:` definition, or a node inside a
  provider payload) is logged and skipped so one bad line cannot take
  down the whole config. `strict: true` promotes every such skip to a
  hard load-time error — plus group members/`use:` names that resolve to
  nothing, entries shadowing built-in adapter names, and malformed
  `dialer-proxy` values. Applies on startup and on `PUT /configs`
  rebuilds of those sections; `proxy-providers:` definitions whose
  identity changed are re-validated on rebuild while unchanged defs are
  reused, and their initial *fetch* stays deferred to commit time. It
  is opt-in because it
  rejects real-world mihomo subscriptions that mix in node types meow-rs
  does not support; provider *fetch* failures stay lenient (a transient
  download error starts the provider empty rather than failing the
  config). Also fixes a pre-existing hole where a dropped
  built-in-shadowing `proxies:` entry could still chain the built-in
  adapter via its `dialer-proxy` field. Public API signatures changed:
  `parse_rules_full`, `ProxyProvider::new`, `load_proxy_providers`, and
  `rule_provider::load_providers_prefetched`. (#533)
- **Benchmark coverage for proxied outbound and config-reload paths
  (#558).** `meow-bench` gains a proxied leg (`--proxy-config` +
  `--singbox-binary`): W1–W3 (throughput, latency, conn-rate) run through
  a real VLESS adapter into a spawned sing-box server, reported alongside
  the direct leg as `rust_proxied`/`go_proxied` and compared by
  `bench/compare.py`. A standalone config-reload workload
  (`--only reload`, `--reload-config`, `--api-port`, `--reloads`) holds
  steady echo load while alternating `PUT /configs` between the config
  and a generated variant whose probe rule flips to REJECT, then
  verifies through the datapath that each committed generation actually
  landed — a rejected reload, a 204 that never reached the listener, or
  a post-rate far below the pre-reload baseline all exit non-zero. The
  previously-unwired ADR-0011 footprint collectors are now
  runnable as `--only idle` (M-idle, N idle conns + RSS) and
  `--only steady` (M-steady). Harness hardening for conn-heavy runs:
  `RLIMIT_NOFILE` raised toward the hard limit (children inherit it),
  pre-flight port-squatter detection, and early-exit checks on every
  spawned process. `bench.sh` runs all new legs; `bench-daily.yml`
  installs sing-box, archives the per-leg artifacts, and runs the
  criterion micro-benches (`--bench`-pinned so the args reach only
  criterion harnesses). The default perf config now sets
  `max-connections: 0` so measurements aren't clipped by the 256-conn
  listener cap. The superseded `bench.yml` workflow and the unused
  `bench/results/` dir are removed.

- **Opt-in UDP TPROXY for TProxy listeners (#564, Linux/IPv4).** A named
  `listeners:` tproxy entry with `firewall: false` + `udp: true` serves a
  UDP TPROXY datagram path on the same port as the TCP REDIRECT path.
  meow installs no firewall or policy-routing state for UDP — the deployer
  owns the `prerouting` TPROXY rules and fwmark→local-table routing, and
  nothing external is removed on exit. Each inbound datagram's original
  destination is recovered from `IP_ORIGDSTADDR` ancillary data, routed
  through the normal rule engine (`dial_udp`), and replies leave with the
  original destination as source via a per-destination `IP_TRANSPARENT`
  socket. UDP port 53 follows routing rules — no implicit DNS hijack.
  Resource bounds: `max-connections` caps live flows (`0` = unlimited),
  `udp-timeout` (default 60s, `0` rejected) is the per-flow idle eviction,
  and per-flow datagram/byte queues plus a bounded reply-socket cache
  prevent unbounded FD/memory growth. `udp: true` with managed firewall
  or a non-IPv4 `listen` is a config error, and on a non-Linux platform
  the listener fails at startup — no silent TCP-only degrade; an omitted
  `udp` changes nothing (no extra socket, no extra privileges). The
  `GET /listeners` API discloses `firewall`, `udp`, and `udp-timeout` on
  tproxy entries, and `PUT /configs` now validates `listeners:` the same
  way startup does — an entry the boot parser would reject returns 400
  instead of persisting a config that hard-errors on next launch.

- **External firewall management for TProxy listeners (#563).** A named
  `listeners:` entry accepts `firewall: false`, which makes meow skip every
  nftables/pfctl interaction for that listener: no rules installed, probed,
  or removed, and the upstream proxy-IP bypass list is not collected. The
  data plane is unchanged — TCP `REDIRECT` connections are still accepted
  and the original destination recovered — while the deployer owns redirect
  rules, loop-prevention bypasses, and boot-ordering/fail-open semantics.
  The default stays `true` (managed), the `tproxy-port` shorthand always
  keeps managed mode, and a `firewall:` key on a non-tproxy listener parses
  with a warning. Managed-mode setup failures now hint at the opt-out in the
  error message. Documented in `docs/tproxy-gateway.md`,
  `docs/tproxy-macos.md`, and the website listeners/transparent-proxy
  guides.

- **Fetch-through-proxy for proxy-providers and subscriptions** (#625 item
  6). `proxy: <name>` on an HTTP `proxy-provider` — previously parsed,
  warned, and fetched direct — now routes the download through the named
  top-level proxy or group, resolved against the live route map at fetch
  time so the binding follows every `PUT /configs` rebuild (provider-sourced
  node names are not reachable, same as upstream). `proxy: DIRECT` or an
  absent field fetches directly — a deliberate divergence from upstream,
  whose absent field rule-routes the fetch through the tunnel; an
  unresolvable or whitespace-only name fails the fetch loudly rather than
  leaking a direct request past a chain the config declared. Providers
  whose `proxy:` name cannot resolve during the pre-publish startup load
  are flagged and get one deferred fetch after the initial route map is
  installed, matching upstream's resolve-per-request model. The same
  `proxy` key is now accepted on `subscriptions:` entries (meow-rs-specific
  feature) and on `POST /api/subscriptions`; it is resolved identically on
  the manual refresh endpoint and the background refresh loop. A named
  `proxy:` on a `file` provider warns and has no effect (there is no
  fetch to chain); whitespace-only values are rejected everywhere —
  provider build, `PUT /configs` validation, and `POST` — matching
  `dialer-proxy` posture.

### Changed

- **TCP tracking without an external controller (#626).** Store only
  cancellation handles when `external-controller` is absent at startup,
  while preserving full API tracking by default for embedders. Headless
  registry keys follow the handle lifetime rather than a cumulative
  counter, avoiding exhaustion on 32-bit targets. `ConnectionGuard::id()`
  now returns `Option<Uuid>`: `Some(id)` for API-tracked connections and
  `None` for headless connections.

- **`AppState::config_mutation_lock` was removed** — the per-state mutex
  serialised only `swap_config_and_reconcile_tun`, whose every caller
  already holds the process-global `CONFIG_MUTATION` lane. The nested
  lock added no exclusion; the lane is now the sole serialisation of the
  read-old → write-new → TUN/DNS-reconcile sequence (issue #543).
  Embedders constructing `AppState` literals drop the field.
  `POST /api/config/save` now holds the lane too, so a save cannot
  snapshot mid-commit state (e.g. a `tun.enable` the runtime is about
  to roll back).

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

- **lru 0.16 → 0.18.4.** Clears RUSTSEC-2026-0253 (`LruCache::pop()` not
  panic-safe, fixed in 0.18.2). Not reachable here — the release profile is
  `panic = "abort"` and the DNS cache / fake-IP keys (`Arc<str>`, `SmolStr`,
  `IpAddr`) have no panicking `Drop` — so no behaviour change; the lock loses
  its last `hashbrown` 0.16 copy (lru now shares the existing 0.17).

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

- **CI and local builds share a pinned toolchain.** `rust-toolchain.toml`
  pins channel 1.98.1 (with `rustfmt`/`clippy`), so every cargo invocation
  in the checkout — CI steps and local runs alike — resolves the same
  rustc/clippy/rustfmt; a floating `@stable` can no longer fail CI on lints
  that do not exist yet locally. Jobs needing a different toolchain opt out
  explicitly — MSRV via a directory `rustup override` (it stays on
  `rust-version`), the drift canary via `RUSTUP_TOOLCHAIN` — and
  cross-target / llvm-tools jobs now attach components to the pinned
  channel. A weekly
  `toolchain-drift` workflow runs the lint gate on floating `stable` as an
  early-warning canary for the next pin bump. (#533)

- **The `subscriptions:` config key is documented.** The guide now covers
  its wholesale-replace of `proxies:`/`proxy-groups:`/`rules:`, the config
  write-back on every successful refresh, the `-t`-doesn't-fetch boundary,
  and a providers.md contrast note against `use:` provider pools. The
  proxy-provider `interval` field is also corrected: no scheduled refresh
  exists for proxy providers. (#533)

### Fixed

- **DNS forwarding preserves upstream error responses for non-address queries** —
  TXT, MX, HTTPS, and other non-A/AAAA queries retain the upstream response code
  instead of reporting `NOERROR` for `NXDOMAIN`, `SERVFAIL`, or `REFUSED` replies.
  This also preserves configured `rcode://name_error` nameserver-policy responses
  for non-A/AAAA queries.

- **A non-ECH mid-handshake TLS failure no longer corrupts ECH state**
  (#572). `SSL_get0_ech_retry_configs` is only legal after an
  authenticated `SSL_R_ECH_REJECTED`, but the self-heal path read it on
  any handshake failure when ECH was configured: debug builds hit
  BoringSSL's `assert(0)`, and release builds stored a 5-byte malformed
  placeholder into the layer's ECH config so every subsequent connect
  failed at `set_ech_config_list`. The read is now gated on a real
  mid-handshake `SSL_R_ECH_REJECTED` failure
  (`handshake_failed_ech_rejected`, covered by C17 in
  `boring_tls_test`).

- **Provider-sourced group members are now health-checked** (#543 item 1,
  #555). The periodic sweep and `GET /group/{name}/delay` resolved
  `group.members()` names through the route table, where `use:` /
  `include-all` provider members are not keys, so a `use:`-only
  `url-test` / `fallback` group woke every interval to probe nothing,
  never became `alive`, and the delay endpoint returned `{}` for it. The
  `Proxy` trait gains `member_proxies()`, which every group implements
  over its static members *and* provider slots; both callers probe
  through it. Providers have no scheduled check of their own yet.

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

- **A deleted subscription's payload could resurrect on a raced
  refresh.** `POST /api/subscriptions/{name}/refresh` and the scheduled
  refresh loop both resolve the URL and fetch before taking the mutation
  lane; if the subscription was deleted meanwhile, the fetched
  proxies/groups/rules were committed unconditionally. The endpoint now
  re-verifies the subscription exists inside the lane and returns 404
  otherwise (409 if the same-name entry was re-added with a different
  URL), and the loop discards the payload on the same recheck. The
  loop also keeps the lane through its disk save so the file's last
  writer follows commit order (issue #543).
- **Concurrent config saves could publish a torn file.** Every writer
  shared the same `{path}.tmp` scratch name, so one save's
  create+truncate could land inside another's `write_all` and the
  victim's `rename` would publish the mixed file. Saves now use a
  unique scratch name per call, and the scratch is swept when the write
  or rename fails so repeated failures can't fill the config dir.
  The same fixed-scratch splice affected rule-provider cache writes
  (`{name}.tmp`), proxy-provider cache writes (not even atomic),
  selector-store persistence (`{path}.json.tmp`), fake-IP snapshots,
  and geodata downloads (`with_extension("tmp")`, which also collided
  for same-stem targets like `Country.mmdb`/`Country.yaml`) — all now
  write through unique per-call scratch names (issue #543).

- **AnyTLS UDP-over-TCP reads poison the conn on an incomplete frame**
  (feature `anytls`). `AnytlsPacketConn::read_packet` consumed the uot
  address + length + payload incrementally under the stream's reader
  mutex — a dropped/cancelled read released the lock mid-datagram and
  every later read silently parsed payload bytes as frame headers, the
  same desync class the trojan/vless poison fixed in #545. The shared
  `PoisonOnIncomplete`/`check_not_desynced` pair now covers `read_packet`
  (with the write side fail-fasting on an already-desynced conn, since
  each anytls write is one atomic frame enqueue and cannot itself tear
  framing) (issue #543).

- **A bare `Fin` before `SynAck` no longer hangs the anytls dial**
  (feature `anytls`). `Session::handle_frame`'s Fin arm evicted the
  stream from `streams`/`stream_receive_tx` but never notified the
  pending synack-waiter — the client keeps `Arc<Stream>` so `synack_tx`
  stayed alive and `synack_rx` pended with no wake of its own (internal
  bound 30 s; the 5 s dial deadline surfaced first). A server that FINs
  instead of SynAck-erroring a refused stream now marks it closed
  locally and wakes the waiter immediately with `StreamClosed`,
  producing a clean dial error (issue #543). The outbound-Fin eviction
  in `process_stream_data` now notifies symmetrically — `open_stream`
  is pub, so an out-of-tree caller can hold a live waiter across a
  local close — and runs after the writer's `select!` so a racing
  session close can no longer drop it mid-eviction. A `SynAck` carrying
  an error payload now evicts and closes the stream too, so callers
  that dropped the receiver no longer leak map entries.

- **Scheduled subscription refreshes no longer reset `select` group
  choices or drop provider-backed group members.** The refresh loop
  rebuilt each fetched candidate with `rebuild_from_raw_with_resolver`,
  which wires no `SelectorStore` — every `select` group in the committed
  config fell back to its first member on each refresh, discarding the
  user's persisted pick until a manual reload rebuilt through the API
  path. `use:`/`include-all` groups now also resolve against the live
  provider registry, keeping provider slot, health, and fetched state
  instead of a detached empty map. The loop now rebuilds via
  `rebuild_from_raw_runtime`, matching `PUT /configs` (issue #543).

- **Geodata DB refreshes now republish the resolver.** When the
  ASN/geosite DB files were replaced on disk, the geodata paths rebuilt
  routing but left the running resolver's `geosite:` nameserver-policy
  matchers bound to the DB generation captured at DNS publish time — a
  `geosite:`-only policy was never republished at all (the
  PUT-vs-candidate input diff does not count geosite keys), and a
  `rule-set:` policy only republished when an unrelated `PUT /configs`
  triggered it. Both geodata commit paths (startup-fetch and the
  periodic auto-update loop) now reparse and republish the resolver
  inside the mutation lane, binding the same live rule-provider map the
  rebuilt rules use (issue #543). The FFI-visible
  `geodata_fetch::run_on_startup` / `auto_update_loop` signatures gain a
  `dns_server` handle parameter for this.

- **`lazy` proxy groups no longer count housekeeping traffic as use.** A
  `lazy` group is only probed after real traffic uses it, but the marker
  distinguishing probe dials (`ConnType::Tunnel`) did not survive two
  internal paths: `dialer-proxy` chained dials rebuilt metadata as
  `ConnType::Inner`, and provider/geodata downloads plus DNS-via-proxy
  exchanges constructed `Inner`/`Http` metadata directly —
  so a `lazy` group referenced as a node's `dialer-proxy` or used for
  downloads was probed every interval forever, silently degrading `lazy`
  to eager. `Metadata` now carries an `internal` flag for housekeeping
  traffic; `TcpDialer::dial`/`dial_addr` take it from the caller's
  metadata and `ProxyDialer` copies it onto the reconstructed metadata
  (as does the relay chain's next-hop rebuild), the internal HTTP fetcher
  and the DNS proxy exchange set it at construction, and group usage
  accounting skips both it and the existing
  `Tunnel` marker via `Metadata::is_internal()`. Mux session-establishment
  dials deliberately stay user-classed — a shared mux conn exists to
  serve user streams regardless of which dial triggered it — and pooled
  kcptun session establishment follows the same rule: it is the only
  dial signal a lazy front hop sees for that chain.

- **`select` and `relay` groups now warn when they carry fields they
  ignore.** Both accept `url`/`interval`/`lazy`/`tolerance`/
  `expected-status` in the shared group shape but run no probe loop, and
  `relay` also dropped `use`/`include-all`/`include-all-providers`/
  `filter`/`exclude-filter`/`exclude-type` silently (upstream relay
  accepts provider members; ours is static-only). Each inert field now
  logs a one-line warning at
  parse — previously `relay` warned on `url`/`interval` only and
  `select` on nothing. The remaining divergences are recorded in
  ADR-0002: upstream sweeps static members of every group type since
  mihomo `90bf158` (v1.18.4), and upstream defaults `lazy: true` while
  meow keeps `false` so existing configs see no idle-traffic change.
  `expected-status` on `load-balance` now reaches its probe loop instead
  of being dropped, and `GET /proxies` reports `expectedStatus` for
  load-balance groups like it already does for `url-test`/`fallback`
  (#555).

- **Duplicate `proxy-groups` names are now a hard error, matching
  mihomo's `proxy group %s: the duplicate name` check.** A group name may
  not collide with a built-in (`DIRECT`/`REJECT`/`REJECT-DROP`/
  `COMPATIBLE`/`PASS`/`PASS-RULE`), a declared `proxies:` entry, or
  another group. Previously the multi-pass
  group build resolved duplicates as "last successful build wins" in the
  registry while parent groups captured member `Arc`s eagerly — a
  same-named group built in a later pass replaced the registry entry
  while already-built parents kept the superseded instance, so
  `proxies["child"]` and `parent`'s member could be two different groups
  (#561).

- **Cyclic `proxy-groups` declarations are now a hard error, matching
  mihomo's `proxyGroupsDagSort` rejection.** The group-membership graph
  is validated on the declared config before construction and reports
  the actual cycle path (`proxy-group cycle detected: A -> B -> A`).
  Previously a cyclic set never satisfied the dependency-aware build
  passes, so the lenient fallback silently dropped the unresolvable
  edges and accepted an order-dependent, truncated graph — e.g.
  `A: [B, DIRECT]` / `B: [A]` could build `A` as `[DIRECT]` only.
  Self-references are rejected the same way. Provider slots
  (`use:`/`include-all`) and `include-all-proxies` resolve to leaf
  nodes only and cannot close a cycle; acyclic forward references with
  missing leaf members keep the lenient #536 behavior (#562).

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

- **The `dialer-proxy` by-name registry no longer pins every superseded
  route generation.** Chained adapters held a strong `Arc` back to their
  build's registry, closing a `registry → proxy map → adapter → registry`
  reference cycle: each config reload leaked the entire previous proxy map
  for the life of the process. The registry cell is now held weakly by the
  adapters and owned per generation by the route table (plus a keepalive in
  rule-provider fetch contexts and the startup `Config`), so a replaced
  generation is freed once its last owner drops — and a chained adapter that
  outlives its generation fails closed instead of silently dialing direct.
  Because a DNS `#name` nameserver snapshots adapters at resolver-build
  time, the resolver is now rebuilt on every API commit / subscription
  refresh whenever either the old or candidate config uses proxy tags — the
  only way to keep its chained upstreams bound to a live generation.
  (#533)

- **Startup prefetch no longer bypasses `dialer-proxy` chains.** The
  pre-registry rule-provider payload prefetch and `ensure_geodata`'s
  download proxy were built by re-parsing raw `proxies:` entries — a
  provider fetch through a chained node egressed without its front hop.
  Both now share one pre-registry proxy layer built by the same code path
  as the runtime map — `dialer-proxy` chains, groups, and GLOBAL included —
  published into a private registry cell for the fetch's duration, so a
  chained or group front hop resolves exactly as it will at runtime. A
  rejected layer aborts the build before any fetch can egress — the same
  validation error the real build would report — and a `proxy:` name the
  layer cannot resolve is skipped and retried against the full registry
  rather than egressing unchained. (#533)

- **`load-balance` groups now balance provider members.** `use:` /
  `include-all` on a `load-balance` group were parsed but dropped with a
  warning — only static `proxies:` entries were balanced, and a
  provider-only group built empty so every dial failed. The group now
  carries the same live `ProviderSlot` set as selector/url-test/fallback:
  provider members join the pick space (statics first, then slot order)
  for both round-robin and consistent-hashing, a provider refresh is
  visible to the next selection without a config reload, and `members()`,
  `alive`, `support_udp`, and delay reporting all see the combined set.
  Load-balance also gains the dial-failure escalation its siblings already
  had: a member that keeps failing dials is marked dead between sweeps,
  complementing the periodic sweep, which probes provider members too via
  `member_proxies()`. (#533)

- **Lazy rule matching no longer warns twice for the same missing
  target.** The two-phase lazy matcher warned inline when a matched rule
  named a missing/dead adapter; when a later rule then demanded IP or
  process enrichment (`NeedsEnrichment`), the strict re-scan warned the
  same match again — two identical warnings per connection. Phase one now
  buffers missing-target matches and emits them only when it reaches a
  final outcome (`Matched`/`NoMatch`); on `NeedsEnrichment` the buffer is
  dropped because the deterministic strict re-scan re-fires each skip
  exactly once. Strict `match_rules` behaviour is unchanged; the buffer
  keeps up to two skips inline, so a dead-target match stays
  allocation-free in the common case. (#533)

- **`PASS`, `PASS-RULE` and `COMPATIBLE` now exist as real built-ins and
  the match loop honours their upstream semantics.** Rules targeting
  `PASS` — or a group whose `unwrap_proxy` chain contains it — are skipped
  silently (mihomo's `continue GetRules`), and inner rules inside a
  `sub-rules:` block resolving to `PASS-RULE` (by name or by adapter type,
  upstream's `CheckPassRule`) skip to the next inner rule. Top-level
  `PASS-RULE` behaves like `REJECT`, and `COMPATIBLE` dials direct while
  carrying its own adapter type, matching upstream. `PASS`, `PASS-RULE`,
  `COMPATIBLE`, and `REJECT-DROP` are filtered out of the auto-created
  `GLOBAL` member list (only DIRECT, REJECT, and user entries seed it);
  `COMPATIBLE` remains usable as a rule target and group member. To support
  side-effect-free chain probing, `ProxyAdapter::unwrap_proxy` gained a
  `touch` flag (upstream `Unwrap(metadata, touch)` parity): `false` peeks
  without advancing round-robin counters or recording usage stats.
  `Rule::match_and_resolve` now takes a `&dyn TargetProbe` — a plain
  `Fn(&str) -> bool` closure still satisfies it (`true` → usable, `false`
  → missing-and-warned). Both are breaking trait changes for external
  implementers. (#533)
- **`dialer-proxy` on provider-sourced nodes is no longer silently ignored
  (issue #489).** Proxy-provider payloads carrying `dialer-proxy` were parsed
  as if the field were absent — the node dialed its server directly, leaking
  past a chain the subscription declared. Provider nodes now get the same
  treatment as static `proxies:` entries: an injected by-name dialer for
  adapter types that support it, the relay-based `DialerProxyAdapter`
  fallback for the rest, re-applied on every provider refresh. The
  provider-level `dialer-proxy` field and `override.dialer-proxy` (mihomo
  `OverrideSchema`) are honoured with upstream precedence — `override` >
  provider > node, the stronger levels writing unconditionally — and a
  malformed `dialer-proxy` value or `override.dialer-proxy` rejects the
  node/provider instead of silently dialling direct. The same discipline
  now covers static `proxies:` entries: values are trimmed (`" front "`
  resolves `front`), `""`/`~` unset the chain and
  `override.dialer-proxy: ""` clears the lower-level chain (mihomo parity),
  and a malformed value under lenient binds a never-resolving target so
  the node fails its dials loudly instead of warn-skipping to direct.
  Payload YAML merge keys
  are expanded so a merged `dialer-proxy` is honoured too. Dialer names resolve against
  the *live* route map at dial time (mihomo's by-name model: top-level
  `proxies:`/`proxy-groups:` entries, not sibling provider nodes) via a
  registry the tunnel republishes on every routing install. A chain that
  would recurse through provider group membership — unknowable to the static
  cycle check — degrades to a named dial error at 16 hops instead of
  overflowing the native stack; the same bound now also guards the
  `DialerProxyAdapter` relay path.

  Breaking for crate consumers: `Config` gains a
  `provider_dialer_registry` field (distinct from the existing
  `dialer_registry` generation cell — this one is the persistent registry
  provider nodes resolve through); `ProxyProvider::new`,
  `load_proxy_providers`, and `parse_proxy_provider_node` take the
  registry/dialer arguments; `rebuild_from_raw_runtime` and
  `subscription_refresh::run_loop` take the registry; `ApiServer::new`
  gains a `provider_dialer_registry` parameter and `routes::AppState` the
  same public field; and `RouteTable::proxies` changes type from
  `HashMap<SmolStr, Arc<dyn Proxy>>` to `Arc<HashMap<…>>` so installs can
  republish by Arc bump. Embedders must additionally wire
  `Tunnel::set_dialer_registry(config.provider_dialer_registry.clone())`
  once at startup — skipping it leaves every provider-sourced `dialer-proxy`
  chain failing closed at dial time.
- **Four queueing/capacity hazards closed across the UDP and DNS hot
  paths.** (a) SOCKS5-UDP session establishment (resolve → route →
  `dial_udp`) no longer runs inline on the association read loop — each
  destination gets a task fed by a bounded per-session queue (64
  datagrams), so one slow destination can no longer stall every other
  destination; per-destination ordering is preserved and the table is
  capped at 1024 sessions with least-recently-active eviction. (b) The
  DNS server replaced its fixed 4-worker pool with answer-inline fast
  paths — hosts, fake-IP, fresh cache hits, and IPv6-disabled AAAA are
  served on the receive loop — plus one task per upstream-bound query
  under a 512-permit semaphore; saturation drops are now counted
  (`BoundDnsServer::dropped_queries`) and warn-logged on a power-of-two
  cadence instead of being silently discarded. (c) The TUN UDP flow
  table is bounded (1024 flows, dead-first then LRU eviction) and
  `dns-hijack` answers are bounded (64 in flight) with locally-decidable
  queries answered inline; live flow occupancy is exposed via
  `TunHandle::udp_flows` / `Tunnel::tun_udp_flow_count`. (d) PROCESS-*
  rule enrichment no longer runs the synchronous `/proc`/`libproc`
  socket scan on Tokio workers — it offloads to the blocking pool, and
  on Linux a 100 ms socket-table cache plus a 1 s inode→process cache
  (4096-entry cap) turn bursts into map hits. (#515)

  Breaking for crate consumers: `TunnelInner::resolve_proxy` and
  `resolve_proxy_lazy` are now `async` (same `Option<ResolvedTarget>`
  return) so PROCESS-* enrichment can offload to the blocking pool;
  `TunHandle` gains a `pub udp_flows` field (breaking struct-literal
  construction) and `TunReady::Ready` is now a struct variant carrying
  it; and `meow_dns::server::LocalAnswer` is newly public for the TUN
  dns-hijack inline-answer path.

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
  members are still not swept. (`use:` / `include-all` provider members were
  ignored with a warning when this landed; they now balance — see the
  provider-members entry above.) See #485.

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

- **`tun:` parameter changes now restart the running listener.** A `PUT
  /configs` that left `tun.enable: true` untouched but changed `mtu`,
  `auto-route`, `dns-hijack`, the address fields, or the inherited
  `max-connections` cap committed the new raw while the listener kept
  running on the old parameters — the two silently diverged until the next
  restart. The reconcile now diffs the parsed `TunConfig` (not just
  `enable`) and restarts a listener on any semantic difference, alongside
  the existing fake-IP-input trigger; no-op respellings and warn-only
  ignored fields do not bounce the device, a dead-but-enabled listener is
  respawned rather than skipped, and a restart failure rolls `enable`
  back to `false`. `PUT /configs` also validates the `tun:` section at
  admission — an unparsable section is a 400 (bypassed by `?force`)
  instead of being committed and tearing the healthy listener down when
  the restart hits the spawn-side parse error.

- **VMess body ciphers no longer pay for unused key schedules.** Every
  connection built two `BodyCipher` objects — one per relay task — and each
  expanded *both* directions' AEAD key schedules, so four schedules were
  computed and two dropped unused (the boxed AES-128-GCM schedule is the
  expensive half). `BodyCipher` now has directional constructors
  (`new_writer`/`new_reader`); the unbuilt direction is a distinct `Unbuilt`
  variant that hard-errors on misuse rather than passing as the plaintext
  `none` codec. Per-connection cost is halved. (#533)

- **Reloaded `rule-providers` gain or lose their interval refresh task
  without a restart.** Provider refresh loops were spawned once at
  startup over the startup-era registry, so a `PUT /configs` or
  subscription refresh that added, removed, or re-`interval`ed an HTTP
  rule provider never gained or lost its background task. A new
  `RefreshSupervisor` (`meow-config::rule_provider_refresh`) diffs the
  wanted (name → interval) set against running tasks on every commit
  that swaps the registry — spawning missing, aborting removed or
  interval-changed, and reaping dead loops — and each loop resolves its
  provider by name on every tick so it follows registry swaps. Ticks use
  `MissedTickBehavior::Delay`, so a suspend longer than `interval` no
  longer fires a back-to-back refresh storm. A successful `refresh()`
  also writes the provider's payload cache file now, so a `prefer_cache`
  restart loads the newest refresh rather than the initial-load-era
  file; an `interval` beyond ~10 years is warn-skipped instead of
  panicking its task. Embedders: `ApiServer::new` and
  `subscription_refresh::run_loop` each gained a required
  `Arc<RefreshSupervisor>` parameter. (issue #543)

- **The DNS rebuild now shares the commit's prefetched rule-provider
  payload snapshot.** Its parser context was built from an empty payload
  map — blind to `GEOIP`/`GEOSITE`/`IP-ASN` rules that live only inside
  provider payloads — and the private provider load it runs when no
  shared provider map is in hand re-read the same bytes the routing
  rebuild had just fetched, potentially seeing different file content
  mid-commit. `RebuildResult` now carries the prefetched payload `Arc`
  and every commit path (`PUT /configs`, subscription refresh,
  `apply_raw_to_tunnel`) passes it to the DNS rebuild, so both parser
  contexts scan the same bytes and a private load parses the
  commit-consistent snapshot. Embedders: `reconcile_dns_config` and
  `parse_dns_from_raw` gained a `prefetched_payloads` parameter.
  (issue #543)

- **A destination inside the fake-IP range with no live allocation is now
  dropped, not dialed.** A stale fake IP — left in a client's resolver
  cache across a restart, evicted by pool wrap, or hit by a literal
  connect into the range — kept its `dst_ip` through dispatch, so the
  outbound adapter dialed it. Under TUN `auto-route` the whole fake range
  routes back into the device, so that dial re-entered the listener as a
  fresh flow whose own dial looped again, self-saturating
  `max-connections` in milliseconds (issue #618). `pre_handle_metadata`
  now returns a `#[must_use]` verdict: an in-range destination with no
  live pool allocation and no recoverable hostname is dropped (mihomo
  drops the same class in `preHandleMetadata`), while one still carrying
  a real name — listener-supplied or sniffed (`sniff_host`) — clears the
  stale literal and resolves the name. An IP *literal* in `host` is not a
  name: it is folded into `dst_ip` first (`fixMetadata` parity), so a
  domain-typed literal (`CONNECT 198.18.0.9`, SOCKS5 `ATYP_DOMAIN`)
  cannot bypass the check. Unlike upstream, the range check also covers
  the pool gateway/broadcast — upstream's TUN device *is* the gateway;
  ours is a separate subnet, so a gateway dial loops the same way.
  The drop applies uniformly across TUN, TProxy, SOCKS5/HTTP and
  Shadowsocks inbounds — all eight call sites share the same
  `TunnelInner::pre_handle_metadata` entry point.

  Breaking for crate consumers: `TunnelInner::pre_handle_metadata` now
  returns `PreHandleVerdict` (`Continue`/`Drop`) instead of `()`.

- **Sniffer: fragmented TLS ClientHello no longer loses the SNI**
  (#622). The sniffer peeked at the socket once and parsed whatever was
  buffered; a ClientHello split across TCP segments parsed as a
  truncated record and `sniff_host` stayed empty — sniff-based routing
  failed open. The gather now re-peeks (5→50ms poll, bounded by
  `sniffer.timeout`) until the declared record length is buffered or the
  prefix is provably not TLS. Found by the Docker TProxy e2e. (#623)

- **Issue #621 audit: lifecycle races, firewall ownership, and
  load-balance mihomo parity.** A deep audit of the reported findings
  confirmed and fixed: (1) managed TProxy firewall objects are now
  per-instance — nftables `inet meow_tproxy_<pid>_<seq>`, pf anchor
  `com.apple/com.meow.tproxy.<pid>.<seq>` — so a second managed listener
  no longer replaces or deletes its sibling's rules; startup sweeps only
  the legacy shared names and per-instance objects whose owning pid is
  dead or foreign (live/unverifiable processes keep theirs); (2)
  `load-balance` consistent hashing now follows mihomo's `getKey`
  derivation (IP literal verbatim, domain reduced to eTLD+1 via the
  public-suffix list, else `dst_ip`) with FNV-1a-64 + jump hash over the
  full member list, retry `key+1` ×5 then linear scan, and eligibility
  probed against the group's `url:` — plus a single member snapshot per
  pick closes a mid-selection provider-swap race (the prior src-IP
  affinity hashing was a deliberate divergence that full parity
  supersedes; `strategy: ""` maps to consistent-hashing as upstream);
  (3) `select` group persistence serializes writers and re-snapshots
  under the write lock so a slow writer can't publish a stale map last,
  and a failed write leaves the store dirty so an unchanged-value retry
  still persists (same stale-rename class fixed in the fake-IP file
  store); (4) geodata refreshes now parse before committing, then commit
  rules and the DNS resolver with no await between, so cancellation
  can't split the generation — and `publish_dns` installs the new handle
  before aborting the old server so a cancel can't leave zero DNS
  listeners; (5) rule-provider cache writes moved off the async worker
  into the blocking parse lane and are generation-gated so an older
  refresh can't overwrite a newer cache or in-memory ruleset; (6)
  `.{pid}.{n}.tmp` scratch siblings of atomic-write targets are swept
  (older than 1h, or owned by a dead pid) from the selector cache,
  fake-IP store, raw-config saves, rule/proxy-provider caches, and
  geodata writes — SIGKILL leftovers no longer accumulate; (7) an
  oversized AnyTLS UDP datagram drains through an 8 KiB stack buffer
  instead of allocating per datagram; (8) gost-plugin `certificate`/
  `private-key` file paths hot-reload on change (see the Added entry).
  Residual lifecycle bugs fixed along the way: the TProxy UDP reply
  dispatcher is torn down with its listener instead of idling detached;
  KCP `send()` returns `Err(InvalidMss)` instead of asserting on a
  zero MSS; and AnyTLS session `synack_tx`/`close_error` moved to
  synchronous mutexes so close and FIN handling no longer await while
  holding both stream-map write locks. (#621)

- GEOSITE rules no longer demand a local DNS resolution per connection —
  upstream never resolves for a domain-only matcher, so the demand was
  pure latency plus a DNS-leak surface for proxy-bound names. The
  `no-resolve` flag remains accepted but is now vestigial. (#625)

- AnyTLS sessions now arm upstream's `synDone` watchdog — opening a
  stream (`sid >= 2`) on a negotiated v2+ peer starts a 3 s session
  deadline that any SynAck disarms. A peer that answers heartbeats but
  never SynAcks previously stayed pooled and wedged every later dial for
  the full 30 s per-stream timeout; the session is now closed and
  evicted instead. (#625)

- The Shadowsocks UDP listener no longer runs `resolve` → route →
  `dial_udp` → upstream writes inline on the shared socket loop — a
  single slow destination used to head-of-line block decrypt→dispatch
  for *every* SS client (worse than the SOCKS5 case fixed in #619, since
  this socket serves all clients). Each `(peer, target)` flow is now a
  bounded 64-datagram FIFO queue feeding a spawned task that owns
  establishment, ordered writes, and the reply pump; the loop only runs
  the AEAD-2022 session/replay bookkeeping and queues payloads. Flow
  keys now use the unresolved destination (domain-form targets key by
  host), so two names resolving to one address get independent flows —
  same routing semantics, finer dedup. (#625)

- `proxy-providers` entries now honour `interval:` — a per-provider
  background task refreshes the payload on the timer (`http` refetches
  and rewrites the `path:` cache, `file` re-reads), matching mihomo's
  `resource.Fetcher` pull loop. Previously the field was parsed but never
  consumed, so node lists went silently stale until a manual
  `PUT /providers/proxies/{name}` or a restart. A
  `ProxyProviderRefreshSupervisor` reconciles the task set on every
  committed registry swap — providers added, removed, or re-`interval`ed
  by `PUT /configs` or a subscription refresh gain/lose/respawn their
  task without a restart, and a reused provider object keeps its slot,
  health state, and derived group views. Scheduled and manual refreshes
  serialize through the provider's `refresh_lock`. Refresh semantics were
  aligned with upstream's `Update`/`loadBuf` at the same time: a failed
  tick — transport error OR a document-level parse defect (a 200-OK
  captive-portal page no longer empties the provider under lenient mode;
  `strict` still governs per-node leniency) — keeps the last-good node
  list, a byte-identical payload short-circuits before parse so
  `updated_at` tracks real content changes, the `path:` cache is written
  only after a successful parse, and the cache fallback applies only to
  initial acquisition (a failed refresh no longer rewinds the slot to a
  stale on-disk generation). Provider `health-check` blocks now log a
  warning that they are not periodically scheduled (the manual
  healthcheck endpoint and group health checks still consume them).
  Embedders: `ApiServer::new`, `subscription_refresh::run_loop`, and
  `commit_proxy_providers` take a new `ProxyProviderRefreshSupervisor`
  argument, `AppState` gains a `proxy_provider_refresh` field,
  `commit_proxy_providers` additionally takes the candidate's
  `proxy-providers:` declarations and its `registry` parameter changed
  `&DashMap` → `&Arc<DashMap>`, and `ProxyProvider` gained a public
  `acquire_initial` (initial-load acquisition with the on-disk cache
  fallback that `refresh` intentionally skips). (#625)

- Dead and src-axis rules no longer pin `needs_ip_resolution` /
  `needs_process_lookup`. `SRC-IP-SUFFIX` / `SRC-IP-ASN` previously
  demanded a `dst_ip` resolution the match never reads (every
  hostname-bearing flow paid a wasted resolve plus a DNS-leak surface);
  composite rules (`AND`/`OR`/`NOT`/`SUB-RULE`/classical rule-sets)
  leaked the demands of provably-dead children — e.g. an AND tree with a
  dead child, a `GEOIP`/`SRC-GEOIP`/`IP-ASN` payload absent from the
  loaded index, or a `PROCESS-NAME`/`PROCESS-PATH` rule on a platform
  without `find_process`. Such rules are now pruned at compile time and
  each prune is logged (rule type, payload, adapter); dead children stop
  contributing demands to live composites, and a logic tree that folds
  to an unconditional match keeps no demand at all. One intended,
  observable consequence: a dead rule can no longer be the sole demand
  carrier that resolves a hostname a *downstream* `no-resolve` IP rule
  would have matched against — such flows now evaluate the IP rule
  without an address. Rules that merely sniff a `sniff_host` without a
  resolvable `host` also stop triggering a pointless resolution
  attempt (the enrichment input gate now matches the field that
  enrichment actually resolves). `LazyMatchOutcome` is `#[must_use]` —
  dropping a `NeedsEnrichment` silently loses buffered dead-target
  warnings. (#625)

- DNS answers for non-A/AAAA queries (TXT, MX, SRV, HTTPS, …) are now
  relayed from the upstream response instead of being rebuilt from its
  answer section alone. The authority section (negative-cache SOA,
  RFC 2308), additional-section glue (MX/SRV target addresses), and the
  upstream flag word (AA, response code) now reach the client verbatim;
  the rewrites are per-hop identity — transaction id, opcode echoed from
  the request, the question echo, RD/CD echoed from the request,
  `recursion_available` asserted, and EDNS, where the upstream's OPT is
  dropped and a minimal response OPT (flag-day payload 1232, DO echoed)
  is synthesized only when the client query carried one
  (RFC 6891 §6.1.1). The name sent upstream is the wire-faithful
  decoded question name rather than a re-parsed text rendering, so
  labels containing a literal dot or non-UTF-8 bytes reach the
  upstream as the client sent them. AD is forwarded only to clients
  that asked for DNSSEC processing (RFC 6840 §5.8); TSIG/SIG records
  that cannot verify client-side are removed from the additional
  section. Question validity is enforced on both arms before
  dispatch: a stray response packet (QR=1) is dropped silently —
  answering one would ping-pong forever between two forwarding
  resolvers — a non-IN class or non-QUERY opcode gets NOTIMP, and a
  compressed/extended leading QNAME is dropped silently — none of
  which spends an upstream round-trip; error responses carry a
  response OPT when the request had one. On the generic path a packet whose
  declared record counts exceed what the datagram could physically
  contain is FORMERR-ed before the decoder reserves memory for them,
  a malformed packet hickory rejects gets FORMERR, and EDNS version
  negotiation answers BADVERS for `version > 0` (RFC 6891 §6.1.3).
  An extended rcode a non-EDNS client cannot express becomes SERVFAIL
  instead of a misleading low nibble, and an upstream or encode
  failure answers SERVFAIL instead of a cacheable NXDOMAIN. Fake-IP
  `ipv4hint`/`ipv6hint` stripping now also covers HTTPS/SVCB records
  carried in the authority or additional sections, gated per record
  owner in the same wire form the fake-IP pool keys on so non-faked
  names keep their `ipv4hint` (`ipv6hint` is stripped for every owner
  whenever `ipv6` is off, which is the default). The REST API
  `GET /dns/query` route relays
  non-A/AAAA queries through the same path and serializes the upstream
  status, flag word, and all three record sections. (#632)

- Snell UDP-over-TCP writes are now cancellation-safe (#625 items 3/15/16).
  A `write_packet` future dropped mid-frame previously left the AEAD stream
  torn — the next datagram would append after a half-written v3 frame or
  clobber undrained v4 pending bytes, silently desyncing every following
  datagram for the life of the session. The packet conn now poisons on an
  incomplete frame write (the same `PoisonOnIncomplete` pattern as the
  trojan/vless packet conns), so later writes — and reads, since the uplink
  is no longer trustworthy — fail fast and let the tunnel tear the session
  down. The same tear guard covers the non-poll `write_packet_frame` /
  `poll_write_packet_frame` entry points: a fresh frame write on a torn
  stream errors instead of emitting after a torn prefix, while a re-poll
  resuming an in-flight write (the `PacketFrameProgress` resume token) is
  unaffected. `read_packet` also reuses one lazily allocated frame buffer
  per connection instead of allocating a fresh 16 KiB vector per datagram
  (ADR-0008).

- `RULE-SET,<name>,<adapter>,src` is now honoured instead of silently
  ignored (#625 item 11). Upstream mihomo parses an `isSrc` option for
  rule-set entries and the `IP-CIDR`/`IP-CIDR6`, `IP-SUFFIX`, `GEOIP`, and
  `IP-ASN` leaf rules; meow-rs previously parsed the trailing flag but
  still matched `dst_ip`, silently misrouting ported configs. The flag is
  now implemented with upstream `SwapSrcDst` semantics: the provider's
  dst-axis matchers evaluate the source tuple on a swapped metadata view,
  `src` implies `no-resolve` (a source-axis match never demands a `dst_ip`
  resolution it cannot use), and the same trailing `,src` flag is
  accepted on the leaf rules — `IP-CIDR,x,DIRECT,src` is equivalent to
  `SRC-IP-CIDR,x,DIRECT`. `,src` on a `domain`-behavior provider is an
  upstream no-op for matching; meow-rs warns instead of silently ignoring
  it. `src` rule-set entries stay on the rule-IR fallback path because
  the `RuleSetRef` lowering carries only the set handle and cannot
  express the swap. Source-axis `IP-ASN`/`IP-SUFFIX` rules now report
  `SRC-IP-ASN`/`SRC-IP-SUFFIX` via `rule_type()` (upstream parity for
  API `/rules` output), and `AND`/`OR`/`NOT` entries inside a
  `classical`-behavior rule provider payload are parsed instead of being
  warn-dropped — the placeholder adapter splice mangled the
  parenthesised payload before. A `MATCH` entry in a classical payload
  is now rejected for the same reason: it spliced into an always-true
  `FinalRule` and silently made the whole provider match every
  connection; a `MATCH` leg inside `AND`/`OR`/`NOT` is likewise rejected
  at any depth (upstream `payloadToRule` parity), and entries with an
  empty or missing payload (`DOMAIN-SUFFIX,`, `DOMAIN-KEYWORD,`, a bare
  `DOMAIN-KEYWORD`) are rejected in classical sets and logic groups —
  they would otherwise splice into always-true members (an empty
  substring/suffix/regex matches everything). Logic-rule adapter
  selection now mirrors upstream `ParseRulePayload` — the *last* field
  after the parenthesised payload is the target, so a trailing
  `AND,((A),(B)),Proxy,src` resolves adapter `src` (missing → warn +
  skip) instead of either silently routing via `Proxy` on the
  destination axis or folding `Proxy,src` into a dead adapter name.
  `DOMAIN-REGEX` payloads containing commas are rejected inside logic
  groups and classical rule-sets: upstream comma-protects them but our
  grammar cannot, and truncating would silently match a different regex.

- TUN startup is now serialized with `PUT /configs` and rolls back on
  failure (#625 item 4). Initial bring-up waits up to
  `TUN_STARTUP_TIMEOUT` (300 s) for device readiness while holding no
  lock; a concurrent config mutation committed `tun.enable: false` and
  its `stop_tun` no-opped on the still-empty handle slot, so the late
  `Ready` published a live device the committed config said was down —
  the committed config diverged from the running state — and a changed
  `tun:` section left two lwIP generations racing. The Ready arm now re-reads
  the committed config inside the `CONFIG_MUTATION` lane: the handle is
  only stored when the committed section still asks for exactly what was
  built; otherwise the stale listener is torn down (abort + `core_done`,
  same teardown as `stop_tun`) without evicting a successor the mutation
  already installed. Startup failures — `TunReady::Failed`, a dropped
  readiness channel, or timeout — now also roll committed `tun.enable`
  back to `false` (the same rollback `PUT /configs` already had), so the
  stored config never claims TUN is up when nothing runs and a later
  same-config PUT retries off→on instead of early-returning on an
  unchanged diff. The rollback is skipped when a concurrent mutation
  already installed a live listener — that sibling owns the committed
  `tun:` section. A `Ready` whose task exits before publication is
  treated as a startup failure (teardown + rollback) rather than stored
  as a dead handle.
