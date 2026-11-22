# Spec: `smux:`/`mux:` `brutal-opts` (issue #974 — last mux gap)

Evidence: mihomo v1.19.34 darwin/arm64 `-t` runs + symbol table (`sing-mux@v0.3.12`
`brutal.go`/`brutal_linux.go`, `adapter/outbound/singmux.go`,
`common/utils/mbps.go` — all fetched verbatim and matched to binary symbols:
`WriteBrutalRequest`, `ReadBrutalResponse`, `(*Client).brutalExchange`,
`SetBrutalOptions`, `proxy:"brutal-opts,omitempty"`).

## Upstream contract

- **Shape** — `smux.brutal-opts: {enabled: bool, up: string, down: string}`
  (`SingMuxOption.BrutalOpts BrutalOption`). `up`/`down` are Go `string`
  fields under mihomo's weak decoder: int/float coerce to string
  (`50`→`"50"`, `50.5`→`"50.5"`); **bool/list/map hard-error**
  (`'brutal-opts.up' expected type 'string', got unconvertible type ...`).
  `enabled` accepts `0`/`1`; string → hard error. Non-map `brutal-opts`
  (scalar/list) → hard error `'brutal-opts' expected a map, got ...`.
  `null` → defaults. Unknown sub-keys (`debug:`) tolerated. Whole map is
  shape-decoded **even when `smux.enabled: false`** (verified: garbage
  `brutal-opts` under disabled smux still errors). No `BrutalOption.debug`.
- **Rate parse** (`utils.StringToBps`, `common/utils/mbps.go`): `""`→0;
  pure-int string → `N Mbps`; regex `^(\d+)\s*([KMGT]?)([Bb])ps$` —
  K/M/G/T = 1e3/1e6/1e9/1e12 (decimal, fallthrough mul), lowercase `b` ⇒
  `/8` (bits), `B` ⇒ bytes. No trim, case-sensitive units, no floats,
  negatives → 0, `ParseUint` overflow → 0, `n*=v` wraps u64.
  **Unparseable → silent 0, never an error** (verified `-t`: `up: abc`,
  `-5`, `50.5`, null, missing — all pass).
- **Wire** (per *new carrier session*, inside `offerNew`, under the 5 s
  `TCPTimeout`): open mux stream to FQDN `_BrutalBwExchange` port 0
  (normal sing-mux stream request, flags=0); write `receiveBPS` (client
  `down` in BPS, u64 BE); read sing-mux status byte (existing
  `MuxStream::poll_response`) then `[ok u8]` → ok=`u64 BE
  serverReceiveBPS` | !ok=`uvarint len + msg` ⇒ error `remote error: msg`.
  Then `sendBPS = min(own up, serverReceiveBPS)` and apply to the
  **physical socket**; stream closed. Server-side mirrors
  `min(server.up, client.down)`.
- **Socket apply** (`brutal_linux.go`): `setsockopt(IPPROTO_TCP,
  TCP_CONGESTION, "brutal")` then `setsockopt(IPPROTO_TCP,
  TCP_BRUTAL_PARAMS=23301, {rate u64, cwnd_gain u32=20}, 16)` on the
  conn's bottom `syscall.Conn` (unwraps TLS/proxy wrappers — i.e. the
  *front hop's* socket under `dialer-proxy`; mux-over-mux fails
  "nested multiplexing is not supported"). Requires apernet's tcp-brutal
  kernel module. **Client-side apply failure is Debug-log, non-fatal**;
  **exchange failure is fatal to that carrier dial** → node down vs a
  non-brutal server. Non-Linux stub returns "TCP Brutal is only
  supported on Linux" → debug; the exchange (and `down` negotiation)
  **still runs on macOS/Windows**.
- **Pool**: `brutal.Enabled` pins every stream to `sessions[0]` — the
  carrier pool collapses to one connection; max/min-streams knobs are
  dead weight under brutal.

## meow integration

1. `crates/meow-proxy/src/mux/brutal.rs` (new, feature `mux`):
   `MuxBrutal{send_bps, receive_bps}`; `BRUTAL_EXCHANGE_DOMAIN =
   "_BrutalBwExchange"`; `string_to_bps(&str)->u64` (exact upstream
   semantics incl. silent-0 and wrapping mul); LEB128 `read_vstring`.
2. `crates/meow-proxy/src/mux/client.rs`: `MuxOptions.brutal:
   Option<MuxBrutal>` (Default `None`). `offer()`: when `brutal.is_some()`
   pick `sessions.front()` (same CAS-reserve path) else dial — mirrors
   `selectSession`. `create_session()`: wrap `(self.dial)()` in
   `brutal_carrier_scope(cell)`; after `SessionKind` is built (still
   inside `SESSION_SETUP_TIMEOUT`), run `brutal_exchange`: `kind.
   open_stream(domain,0,false)` → `write_all(recv_bps.to_be_bytes())` →
   `flush` → `read_exact(1)` ok-byte → u64 / uvarint-msg → drop stream →
   `rate = min(send,server_recv)` → `carrier.apply_rate(rate)`; any
   error propagates (kills the carrier dial — upstream parity).
   `brutal-opts` + `protocol: muxcool` ⇒ parse-time hard error.
3. `crates/meow-common/src/socket_protect.rs`: task-local
   `BRUTAL_CARRIER: Option<Arc<BrutalCarrier>>` beside `DIALER_OPTS`
   (`BrutalCarrier{sockets: Mutex<Vec<TcpStream>>}`);
   `brutal_carrier_scope`, and `BRUTAL_CARRIER.scope(None,…)` cleared
   inside `resolve_via_hook`/`resolve_host_all_via` (DNS-via-proxy
   sockets must not stash). In `connect_tcp` (beside the #993 keepalive
   apply, line ~732), `#[cfg(all(linux, not(ohos)))]` stash
   `stream.try_clone()` — task-local survives a `dialer-proxy` front's
   `dialer_opts_scope` replacement ⇒ lands on the front's socket =
   Go `Cast[syscall.Conn]` bottom-unwrap. `apply_rate(rate)`: per
   stashed socket — `TCP_CONGESTION "brutal"` (NUL-terminated) then
   `TCP_BRUTAL_PARAMS(23301) {rate, cwnd_gain 20}` (`#[repr(C)]`,
   16 B); failures → `tracing::debug!` (upstream logs Debug, non-fatal);
   empty vec → debug "no kernel socket" (≈ upstream's cannot-convert).
   Non-Linux: stash no-op, `apply_rate` → debug "TCP Brutal is only
   supported on Linux".
4. `crates/meow-config/src/proxy_parser.rs` (~3651): replace warn-ignore
   with `parse_brutal_opts` — run **before** the `!enabled` early return
   (upstream decodes eagerly). Map-check → `enabled` bool (reuse
   `mux_bool_field`) → `up`/`down` weak string (string verbatim; `null`/
   absent → `""`; number → its YAML repr with integral floats normalized
   `50.0`→`"50"`; bool/list/map → hard error `{name}: mux option
   'brutal-opts.up' must be a string or number`), `string_to_bps` at
   parse. `enabled:true` ⇒ `Some(MuxBrutal)` even with
   both rates 0 (exchange still runs, upstream parity). Plus
   `brutal-opts`+`muxcool` hard error and a non-Linux per-node
   `tracing::warn!` (enabled only; the down-negotiation still works —
   warn says rate *cap* is skipped, not the feature).
5. Docs: `docs/specs/proxy-mux.md` ~133 (replace "unsupported" with §4a
   wire/mechanism + single-carrier pin + Linux-only note);
   `docs/gap-analysis.md` smux row; `docs/migration-from-go-mihomo.md`
   add a `smux.brutal-opts` row (B: parse leniency mirrored, socket apply
   Linux-only, non-Linux runs negotiation + warn). `validation.rs`
   top-level `brutal-opts` entry **unchanged** (it covers the node-level
   key, which upstream also rejects).

## Edge cases

- `smux.enabled:false` + malformed `brutal-opts` → hard error (upstream).
- `enabled:true` + zero/unset/garbage rates → exchange sends 0 /
  `min(x,0)` → kernel rate 0 — mirror silently, no warn.
- parallel `connect_tcp_candidates`: stash-all → apply-all (a losing
  candidate may take a wasted setsockopt; closes right after — bounded,
  and the carrier socket is always in the set).
- `dialer-proxy` chains: applies to the front hop's socket; nested
  mux-over-mux → rear cell empty → debug only.
- UDP/`only-tcp`/padding orthogonal; groups/providers unchanged; reload
  posture = new carriers only (same rule as outbound keepalive).
- No kernel-module probe at `-t`/PUT — shape checks only (upstream can't
  check either; failure is runtime-debug).

## Acceptance

- `-t` parity table passes on real mihomo cases; `string_to_bps` table
  test (Mbps/Mbps-bare-int/Gbps/kbps/bps/Bps, lowercase-unit/space/float/
  negative/huge → 0).
- Wire test: scripted duplex peer asserts `_BrutalBwExchange` prefix +
  u64, replies ok/`!ok`+msg → session accepted / dial fails.
- `offer()` pin test: brutal ⇒ single carrier across concurrent opens.
- Linux CI: `apply_rate` on loopback socket ⇒ either Ok (module) or the
  "tcp-brutal kernel module" debug path; capture-scope test proves the
  stash + `resolve_via_hook` clearing.
- D16g test updated: `brutal-opts` no longer warns; `statistic` still
  does; new malformed-shape hard-error cases in vless/ss arms.
