# Test plan: `listeners: type: anytls`

Companion to [listener-anytls.md](listener-anytls.md). Cases are named
after the inbound spec's C1 (config surface), C2 (address/API surface)
and W1–W3 (wire/protocol surface) classes. Everything below is a unit
test — no external node, no Docker.

## C1 — configuration compatibility & validation

`crates/meow-config/src/lib.rs` (`listener_surface_tests::anytls_*`):

| Case | Test |
| --- | --- |
| multi-user, declaration order, SHA-256 digests | `anytls_users_multi_in_declaration_order` |
| empty `users:` = reject-all, warn not error | `anytls_users_empty_is_reject_all_not_an_error` |
| empty username / empty password | `anytls_users_empty_name_and_password_error` |
| duplicate username (parse-level dup-key policy) + duplicate password digest | `anytls_users_duplicate_name_and_password_error` |
| non-string password | `anytls_users_nonstring_password_is_parse_error` |
| no security mode; cert pair; `allow-insecure` plaintext; half pairs; mixed PEM/path forms | `anytls_security_mode_matrix` |
| mTLS/ECH non-empty error — whitespace-only counts (raw value); `""` passes | `anytls_mtls_and_ech_hard_error_only_when_non_empty` |
| `shadow-tls`/`res-tls`/`jls-config` enabled→error, disabled→warn, non-mapping→error | `anytls_front_layers_enabled_error_disabled_warn` |
| `enable: false` / `udp: false` errors; `true` spellings pass | `anytls_enable_and_udp_flags` |
| `padding-scheme` shared-contract validation | `anytls_padding_scheme_validated_by_shared_contract` |
| `users:`/`certificate:` on other types warn; `cipher:`/`kcp-tun:` on anytls warn; `type_name()` | `anytls_foreign_keys_and_type_name` |

## C2 — multi-address & API surface

| Case | Test | Where |
| --- | --- | --- |
| multi-address `listen`, same port on two addresses legal, first address → `NamedListener` pair | `anytls_multi_address_listen_and_port_registry` | meow-config |
| per-segment ports (`port: 0` + `host:port` segments), `listen:port` vs `port` conflict error | same | meow-config |
| secondary address port joins the duplicate-port registry; empty segment error | same | meow-config |
| `GET /listeners` reports `addresses[]`, first `listen`/`port`, no secrets | `listeners_reports_every_anytls_address_and_no_secrets` | meow-api |
| single-address omits `addresses` key | `listeners_single_address_anytls_omits_addresses_key` | meow-api |
| feature gate maps `Anytls` → `listener-anytls`; uncompiled build fails `ensure_inbounds_supported` | `listener_gate_matches_spawn_arms`, `ensure_rejects_uncompiled_anytls_listener` | meow-app |
| `IN-TYPE,ANYTLS` matches only `ConnType::Anytls` | `in_type_anytls_matches_only_anytls` | meow-rules |

## W1/W2 — session protocol (v1 silence / v2 ordering / violations)

`crates/meow-anytls/src/session/session.rs` (`server_protocol_tests`) —
real frames over `Session::new_inbound` + `run_server`:

| Case | Test |
| --- | --- |
| missing `padding-md5` → `UpdatePaddingScheme`, then `ServerSettings{v:2}`, then SYNACK on `handshake_success` | `v2_settings_then_synack_in_wire_order` |
| v1 peer (correct md5): no `ServerSettings`, no SYNACK — next frame is the heartbeat answer | `v1_peer_gets_no_server_settings_or_synack` |
| SYN before Settings → Alert + close | `syn_before_settings_alerts_and_closes` |
| duplicate live SYN sid → ignored (upstream `LoadOrStore`), no Alert, session stays | `duplicate_stream_id_is_ignored` |
| stream-count bound: 129th SYN → bare FIN (upstream refusal), session stays | `v2_stream_limit_refuses_with_fin` |

## W3 — resource bounds & UoT codec

| Case | Test | Where |
| --- | --- | --- |
| per-stream pending overflow evicts only that stream | `per_stream_pending_overflow_evicts_only_that_stream` | meow-anytls |
| SOCKS address decode all families + errors | `socks_addr_decodes_every_family` | `uot.rs` |
| exact `sp.v2.udp-over-tcp.arpa:0` marker; legacy name & non-zero port rejected | `uot_marker_is_exact_and_rejects_never_route` | `uot.rs` |
| uot family table ≠ SOCKS5 table; IPv4-mapped unmap | `uot_family_table_differs_from_socks` | `uot.rs` |
| request/packet framing incl. zero-length datagram, oversize refusal, bind round-trip | `uot_request_and_packet_framing` | `uot.rs` |
| multi-user auth preface: digest match/mismatch, padded preface | `util::auth::tests::*` | `util/auth.rs` |

## W4 — production entry (listener → tunnel)

`crates/meow-listener/src/anytls.rs` (`tests`) — a REAL `run_on` accept
loop + TCP socket + `allow-insecure` plaintext + recording proxy:

| Case | Test |
| --- | --- |
| auth preface → v2 ServerSettings → SYN → SynAck → echo data → refused marker (bare FIN, no ACK, no dial) → peer-FIN closeLocal + recycled-sid stream still ACKs | `production_entry_auth_stream_ack_fin_and_refusal` |
| wrong digest → zero response bytes, socket closes | `production_entry_bad_auth_closes_silently` |

`crates/meow-listener/src/anytls_uot.rs` (`tests`):

| Case | Test |
| --- | --- |
| reply-side death retires session + closes conn (no JoinHandle double-await) | `reply_side_death_retires_session_and_closes_conn` |
| aborted session task still closes its conn (association ownership) | `aborted_session_task_still_closes_conn` |

`crates/meow-app/src/main.rs` (`tests`):

| Case | Test |
| --- | --- |
| second-address bind failure errors AND releases the already-bound group | `anytls_partial_bind_failure_releases_the_whole_group` |

## Still open

- **Live listener end-to-end** (BoringSSL accept → auth → session →
  routed TCP/UoT through a real `Tunnel`) — covered by code path, not
  yet by an in-process integration test; needs a loopback TLS pair and
  is best run once as a manual smoke with a real mihomo client.
- **Second-address bind failure atomicity** — exercised by the startup
  code path; a test would need a port already held, which is
  environment-dependent (doable with a pre-bound loopback socket if
  flake-free on CI).
