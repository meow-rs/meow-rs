# Spec: Extended controller listeners — TLS, Unix socket, named pipe, CORS

Status: Implemented
Owner: pm
Tracks: [issue #974](https://github.com/madeye/meow-rs/issues/974)
Upstream reference: `hub/server.go` (`ReCreateServer`), `adapter/inbound`,
metacubex/chi CORS middleware — probed against the mihomo Darwin binary
(see the issue's empirical appendix for the wire evidence this document
encodes).

## Scope

Mihomo serves its controller on up to four independent endpoints from one
config — plain TCP (`external-controller`), HTTPS (`external-controller-tls`),
a Unix-domain socket (`external-controller-unix`) and a Windows named pipe
(`external-controller-pipe`) — all behind one router, with CORS policy from
`external-controller-cors:`. This batch ports that surface.

In scope:

- `external-controller-tls` — a second TCP listener serving HTTPS with
  BoringSSL, ALPN `h2` then `http/1.1`. Compiled only under the
  `api-tls` cargo feature (see below): in `full`/`default`, out of
  `minimal`.
- `tls.certificate` / `tls.private-key` — the HTTPS identity: inline PEM
  (both values containing `-----BEGIN`) or a pair of file paths resolved
  against the daemon home and `SAFE_PATHS`. Both unset with a declared
  TLS listener generates an ephemeral self-signed identity at bind.
- `external-controller-unix` — HTTP over a Unix-domain socket; relative
  paths resolve under the daemon home.
- `external-controller-pipe` — parsed on every platform, served on
  Windows only (`\\.\pipe\NAME`, byte mode, remote clients rejected).
- `external-controller-cors:` — `allow-origins` and
  `allow-private-network`; under a configured secret, absent and
  present maps serve the same configured-middleware wire shape.
- CLI flags `--ext-ctl-tls`, `--ext-ctl-unix`, `--ext-ctl-pipe` —
  post-load overrides over the matching config keys.
- `external-controller-routing-mark`, `tls.client-auth-type`,
  `tls.client-auth-certificates`, `tls.ech-key`,
  `tls.custom-certifactes` (sic) — parsed and warn-ignored, even under
  `strict: true`.

Out of scope: PEM file watching with last-good-pair fallback (upstream
reloads file-backed identities; meow snapshots them at bind),
`external-controller-routing-mark` enforcement, mTLS client auth, ECH.

## Decoder contract (mirrors mihomo's weak YAML→Go unmarshal)

- The three listener keys and `tls.certificate`/`tls.private-key`
  weak-decode scalars — a string verbatim, a number rendered, a boolean
  `"true"`/`"false"` — and hard-error on sequences and mappings. The
  coercion follows the YAML resolution — under YAML 1.2's core schema
  only `true`/`false` are booleans, so `external-controller-tls: 5`
  parses as `"5"` and `external-controller-tls: yes` keeps the literal
  spelling `"yes"` (quoting changes nothing); the legacy bool spellings
  are honoured only by `allow-private-network`, which is a typed bool.
- `allow-origins` is a sequence; items weak-decode the same way. A bare
  scalar (`allow-origins: "*"`) is a hard error, `[]` is allowed and
  means allow-all.
- `allow-private-network` accepts YAML booleans plus the legacy
  spellings (`yes`/`no`/`on`/`off`/`y`/`n`, any case); numbers and
  quoted boolean strings are hard errors.
- `tls:` must be a mapping (`tls: 5` is a hard error); a null/absent
  `tls:` is fine.
- Top-level `certificate`/`private-key` are **not** aliases for the
  nested keys — mihomo reads them under `tls:` only. meow parses them
  into `extra` and warns *misplaced* with a `tls.*` hint; they never
  feed the listener identity.
- `meow -t` and `PUT /configs` validate decode + shape only: no socket
  bind, no socket unlink/create, no PEM file read, no ephemeral cert
  generation. Like upstream, *every* identity failure — one-sided pair,
  malformed inline PEM, unreadable path, invalid cert/key — defers to
  endpoint bind and merely skips the HTTPS listener; the build keeps the
  raw values.

## Runtime semantics

- All configured endpoints bind at startup and serve the one shared
  `AppState`/router — same routes, same Bearer/origin checks, same CORS
  middleware — concurrently and independently. Any subset may be
  configured; TLS-only and Unix-only are valid.
- The plain `external-controller` bind stays startup-fatal (issue #641).
  The new endpoints are best-effort like upstream: a failed bind/identity
  is logged and skipped (`… — endpoint skipped`), never silently
  downgraded; if every configured endpoint failed, startup logs that no
  controller is available.
- TLS identity resolution is pair-level like upstream, decided at
  endpoint bind: both values containing `-----BEGIN` → inline PEM;
  otherwise both are file paths resolved under home/`SAFE_PATHS` and
  read once (bounded read, regular files only). A *mixed* pair — one
  inline, one path — is rejected before path resolution, and the error
  never embeds the inline material as if it were a path. A chain PEM
  serves leaf-first. Both unset → an ephemeral self-signed RSA-2048
  `localhost` identity.
- A bare `:port` on `external-controller-tls` tries `[::]:port` first —
  dual-stack, `IPV6_V6ONLY` explicitly off, `SO_REUSEADDR` on unix only
  (Winsock's flag permits port hijack, which is why std never sets it
  there) — and falls back to `0.0.0.0:port` when the host cannot do
  IPv6. A hostname resolves to *one* address — its answers are
  reordered v4-first and only the first is bound, never retried —
  upstream's `net.Listen("tcp", …)` behavior; candidate traversal is
  the bare-port wildcard's alone. (The plain `external-controller`
  keeps its pre-existing `0.0.0.0:port` normalization at parse.)
- The TLS listener advertises h2 via ALPN and answers RFC 8441
  extended-CONNECT (`CONNECT` + `:protocol = websocket`) WebSocket
  upgrades on the WS-capable routes — axum's serve layer enables the
  protocol unconditionally, so the routes/auth path understands it
  rather than refusing; `?token=` authenticates those upgrades the same
  as HTTP/1.1's. A `CONNECT` that is not a valid upgrade answers the
  GET-only route's `405` + `Allow: GET` — it never receives the route's
  GET body, which would fake a tunnel — and `CONNECT` never leaks into
  the chi-shaped `Allow` headers.
- The TLS accept loop bounds in-flight handshakes (128) and gives each
  a 10 s deadline so a slow-loris burst cannot stall accept; finished
  handshakes queue for axum (64).
- The no-secret Host/Origin/Sec-Fetch-Site guard compares `Origin`
  against the transport's real scheme — the TLS router clone marks
  requests so a same-origin `https://` dashboard over HTTP/1.1 is not
  rejected as cross-scheme. Over h2 the `:scheme` already says `https`.
- `publish_controller` (the file `meow-cli` reads) stays HTTP-only: a
  TLS address or socket path is never published as an `http://`
  endpoint.
- Headless connection tracking is selected only when *no* servable
  endpoint is configured — servable at startup meaning configured *and*
  compiled into this build (a TLS-only config on a no-`api-tls` build is
  headless).

### `api-tls` build feature

The HTTPS endpoint alone is a cargo feature — `meow-api/api-tls`,
forwarded as `meow-app/api-tls` — because its code cost is real: the
BoringSSL `SslAcceptor` + RSA key generation plus axum's `http2` server
(the `h2` ALPN must actually serve) add ~500 KB to the `minimal` bundle,
so ADR-0007 keeps it in `full`/`default` and out of `minimal`. The Unix
socket and named pipe are platform-gated only — no feature.

Without `api-tls` the surface stays a dead placeholder like the compiled-
out plugin transports: `external-controller-tls`, `tls.certificate` and
`tls.private-key` parse and validate identically (`-t` accepts them),
`PUT /configs` round-trips them for a later restart, but startup warns
`external-controller-tls '…' ignored — the HTTPS controller is not
compiled into this build (feature 'api-tls')` and the endpoint never
binds. The workspace `axum` dependency carries no `http2` — the feature
enables it only on meow-api's edge, so feature unification cannot leak
the h2 server into a no-TLS build.

### Deliberate divergences (Unix socket)

Upstream unlinks whatever occupies the path, binds, `chmod 0666`s it,
serves without auth, and leaves a stale socket on exit. meow:

- refuses a non-socket path and another user's socket;
- refuses a configured path that cannot fit `sun_path` (103 usable
  bytes here) *before* touching the filesystem — the error names the
  path and the limit, and the same check runs on the generated staging
  sibling so a near-limit path cannot bind;
- probes an existing same-owner socket with a 500 ms-bounded connect;
  `ECONNREFUSED` twice (50 ms apart — macOS/BSD refuse once the backlog
  is full, so one refusal is ambiguous) is still not proof of death:
  before reclaiming, the kernel's own socket table is asked whether a
  live process still binds the path — libproc fd enumeration on Apple
  targets, `/proc/net/unix` on Linux/Android (where refusal is already
  conclusive and the table is a second opinion), and a conservative
  "cannot prove" on other unixes, which keeps the file and skips the
  endpoint. Spellings the kernel recorded relative are resolved under
  the *holder's* cwd (`PROC_PIDVNODEPATHINFO` on Apple; the `socket:[ino]`
  fd link → `/proc/<pid>/cwd` chain on Linux), never under meow's own;
  and an enumeration that cannot be fetched whole — the pid list or a
  per-pid fd table still filling its capped buffer — answers "cannot
  prove" rather than a silent "not bound". A live answer means live,
  and a timeout or any other probe error means uncertain: the path is
  left alone and the endpoint skipped;
- before unlinking a verified-stale socket re-stats the path and unlinks
  only when `(dev, ino, ctime, ctime_nsec)` still names the probed file —
  a racing re-bind leaves a *different* socket, which is kept (the
  residual stat→unlink window is inherent: unix sockets have no
  unlink-by-handle);
- binds owner-only `0600` by binding an exclusively-claimed private
  sibling (a `pid`-and-sequence staging name retried on collision, never
  an unconditional unlink of whatever already sits there), `chmod`ing
  it, then publishing into place — the configured path never exists
  with permissive mode; a `chmod` failure fails the whole endpoint bind
  rather than serving a world-accessible socket;
- the publish is atomic *no-replace* — `renamex_np(RENAME_EXCL)` on
  Apple targets, `renameat2(RENAME_NOREPLACE)` on Linux/Android,
  `link()`+drop elsewhere — so a racing occupant's file (another
  daemon's live socket or an unrelated path) is never overwritten;
  `EEXIST` keeps the target and skips the endpoint;
- keeps Bearer auth (and the no-secret origin guard) on the socket —
  like the pipe and TLS transports;
- removes only the socket path it created, via a guard that lives for
  the daemon's lifetime and re-verifies the path is still a socket with
  the same `(dev, ino)` it bound — a swapped or recreated file is left
  alone.

### Windows pipe

Byte-mode `NamedPipeServer` instances, one pending instance always
pre-created, remote clients rejected, `first_pipe_instance` claims the
name. Every instance — the first and each replacement — is created under
an owner-only security descriptor (SDDL `D:P(A;;GA;;;OW)`, a protected
DACL granting the owner all access and nothing else), a deliberate
hardening over upstream's default-ACL pipe that matches the `0600`
posture of the Unix socket. If creating the *next* pending instance
fails after a client already connected, the connected client is still
served and creation retries on the next accept. Serving is
`cfg(windows)`; on other platforms a configured `external-controller-pipe`
warns and is ignored (also at validate time). Windows parity is untested
on real Windows.

## CORS contract (the configured `cors.New` shape)

Mounted identically on every transport, outside Bearer auth so
preflights answer; it does not make actual routes public. Upstream's
middleware selection (probe-verified, issue #974):

| `external-controller-cors:` map | `secret` | Upstream middleware |
|---|---|---|
| present | any | configured path (resolved keys) |
| absent | `""` explicitly | permissive `AllowAll` (`*` grants, combined `vary`) |
| absent | set or unset | configured path on `["*"]`/`true` defaults |

Only an explicit `secret: ""` fires the permissive path — map presence
alone never does. meow mounts the CORS layer only under a configured
secret, so the `AllowAll` row has no meow counterpart: with `secret`
unset *or* `""` the controller mounts no CORS middleware at all and the
Host/Origin/Sec-Fetch-Site guard answers cross-origin preflights 403 —
it already admits only same-origin browser requests, and emitting `*`
grants on top of a 403-rejected origin would leak a false promise.

The configured-path wire shape:

- preflight → always `200` with the `vary` trio (three separate
  headers); CORS headers ride only when origin, method and requested
  headers all pass — a denied preflight is `200` + vary only;
- `allow-origins` entries: `*` or an empty list → literal `*`; glob
  entries match on the first `*` (prefix+suffix, case-insensitive);
  otherwise echo the request `Origin`;
- `Access-Control-Allow-Methods` echoes the single requested method,
  uppercased, from `GET POST PUT PATCH DELETE OPTIONS` — `HEAD` is
  never allowed (weird-but-real, probe-verified);
- `Access-Control-Allow-Headers` echoes the requested header list
  canonicalized (`Authorization`), in request order — but only when
  every requested name passes the upstream allowlist
  `{content-type, authorization, origin}` (case-insensitive); one
  unsupported name denies the whole grant, it is not trimmed. (The
  configured path never emits `AllowAll`'s literal `*` here — a `*` is
  a wildcard to Fetch only for non-credentialed requests, which is why
  upstream's `AllowAll` shape gets away with it.);
- `Access-Control-Max-Age: 300`;
- `Access-Control-Allow-Private-Network: true` only when
  `allow-private-network` resolved true (default) *and* the request
  sent `Access-Control-Request-Private-Network: true` literally;
- actual request → allowed origin echoes/`*(as above) + `Vary: origin`,
  gated on the same method allowlist — an actual `HEAD` from an allowed
  origin earns no `Access-Control-Allow-Origin`.
- A bare `OPTIONS` without `Origin`/`Access-Control-Request-Method`
  is not a preflight — it falls through to the router (405 on `/`).

## Reload contract

Controller addresses, TLS identity and CORS are startup snapshots.
`PUT /configs` validates and commits the new raw document (the keys
round-trip so a restart picks them up) but never binds, unlinks, reads
PEMs or mutates the live listeners/CORS; a change to any of
`external-controller*`, `external-controller-cors` or `tls:` warns that
a restart is required. `GET /configs` and `PATCH /configs` do not
surface the TLS/CORS keys — private key material is never echoed.

## Files

- `crates/meow-config/src/raw.rs` — `RawCors`, `RawTls`, weak-scalar
  field decoders.
- `crates/meow-config/src/lib.rs` — `ApiConfig` extension,
  `ApiCorsConfig` resolution, `has_servable_endpoint()`.
- `crates/meow-config/src/validation.rs` — misplaced/member/platform
  warnings.
- `crates/meow-config/src/safe_path.rs` — `resolve_home_contained`.
- `crates/meow-api/src/cors.rs` — the configured-path CORS middleware.
- `crates/meow-api/src/endpoint.rs` — `bind_tls` (+ BoringSSL acceptor
  builder, handshake driver, ephemeral identity, wildcard-fallback /
  hostname-single-answer resolution) under `api-tls`, `bind_unix` (+
  sun_path preflight, bounded stale probe, kernel-table liveness
  verification, identity-verified reclaim, exclusive staging name,
  `0600` + atomic no-replace publish, dev+ino cleanup guard),
  `bind_pipe` (+ owner-only SDDL ACL, pending-instance preservation)
  on Windows.
- `crates/meow-api/src/lib.rs` — `ApiServer` split: shared state,
  `router()`, `run_on`, `serve_on`, `serve_tls_on`.
- `crates/meow-api/src/routes.rs` — CORS layer mount, `TlsTransport`
  scheme marker, PUT snapshot warning, h2 extended-CONNECT WebSocket
  recognition/auth and `Allow`-header filtering.
- `crates/meow-app/src/main.rs` — CLI overrides, multi-endpoint startup,
  Unix cleanup guard, headless gating.

## Test coverage

- `crates/meow-config/tests/config_test.rs` — parser tests: scalar
  weak-decode, container hard errors, TLS shapes, misplaced keys,
  warn-ignored members, CORS defaults/legacy bools, shape-only pairs,
  `has_servable_endpoint` per-transport.
- `crates/meow-api/tests/api_endpoint_test.rs` — CORS wire shapes (both
  paths, wildcard/empty/glob/denied, HEAD on preflight *and* actual,
  header allowlist denial, PNA, bare-OPTIONS), TLS serving + real
  negotiated-`h2` request + scheme-marker origin guard + h2
  extended-CONNECT WebSocket auth/frame, non-upgrade CONNECT 405,
  orderly-close TIME_WAIT rebind with a no-flag negative probe,
  hostname first-answer bind, configured/bad/mixed-no-leak identities,
  Unix serve/auth/0600/reclaim/refuse/swap-safe-cleanup/relative-home/
  bounded-probe-under-full-backlog with (dev, ino) identity asserts and
  overlong-path named errors, PUT persistence without rebinding,
  GET no-echo.
- `crates/meow-app/src/main.rs` — `--ext-ctl-*` overrides, including the
  empty-override-keeps-YAML rule; `api_endpoint_servable` applies the
  `api-tls` compile gate to the configured set.
