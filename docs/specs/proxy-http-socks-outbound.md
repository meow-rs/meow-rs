# Spec: HTTP CONNECT and SOCKS5 outbound adapters (M1.B-3, M1.B-4)

Status: Approved (architect 2026-04-11)
Owner: pm
Tracks roadmap items: **M1.B-3** (HTTP CONNECT outbound), **M1.B-4** (SOCKS5 outbound)
Depends on: `meow-transport` crate (M1.A) for TLS-wrapping support.
See also: [`docs/specs/transport-layer.md`](transport-layer.md) — TLS transport layer.
Upstream reference: `adapter/outbound/http.go`, `adapter/outbound/socks5.go`.

## Motivation

HTTP CONNECT and SOCKS5 are ubiquitous proxy protocols. Corporate networks
typically expose an HTTP proxy; most proxy subscription formats include SOCKS5
nodes. Both exist as `AdapterType` enum variants in `meow-common`
(`Http`, `Socks5`) with no implementation behind them. Without these, any
config with `type: http` or `type: socks5` proxies fails to parse, blocking
a significant fraction of real-world subscriptions.

Both adapters are small (~150 LOC each) and share the pattern of a
one-shot handshake over a freshly-dialled TCP connection before handing
the stream back as a `ProxyConn`.

## Scope

In scope (both adapters):

1. `HttpAdapter` in `crates/meow-proxy/src/http_adapter.rs`.
2. `Socks5Adapter` in `crates/meow-proxy/src/socks5_adapter.rs`.
3. TCP tunnel via HTTP CONNECT handshake (HTTP/1.1 only).
4. SOCKS5 TCP tunnel (CMD `0x01` CONNECT).
5. Username/password authentication for both protocols.
6. Optional TLS-wrapping of the connection to the proxy server (`tls: true`),
   using the `TlsTransport` from `meow-transport`. SNI defaults to `server`
   field; `skip-cert-verify` as in Trojan.
7. YAML config parser wired in `meow-config`.
8. `AdapterType::Http` and `AdapterType::Socks5` already present in enum —
   no enum change needed.

Out of scope:

- **SOCKS5 UDP ASSOCIATE** (CMD `0x03`): deferred to M1.x. UDP relay over
  SOCKS5 requires a separate UDP socket bound to the relay address returned
  by the server, plus per-packet SOCKS5 framing — non-trivial. `support_udp()`
  returns `false` in M1; `dial_udp()` returns `Err(UdpNotSupported)`.
- **SOCKS4 / SOCKS4a**: not supported. Hard error if somehow requested.
- **HTTP proxy auth schemes other than Basic**: Digest, NTLM, Negotiate —
  deferred. M1 supports Basic only.
- **HTTP/1.0 CONNECT**: upstream uses HTTP/1.1 only. We match.
- **`headers:` injection on non-CONNECT HTTP traffic**: relay is TCP-only
  via CONNECT; we do not intercept HTTP request bodies.
- **Upstream proxy chaining** beyond what relay groups already provide.

## User-facing config

```yaml
proxies:
  - name: corp-http-proxy
    type: http
    server: proxy.corp.example
    port: 8080
    username: alice             # optional
    password: s3cr3t            # optional
    tls: false                  # optional; wraps TCP to proxy in TLS
    skip-cert-verify: false     # only relevant when tls: true
    headers:                    # optional; injected into CONNECT request
      X-Forwarded-For: "1.2.3.4"

  - name: socks5-node
    type: socks5
    server: 10.0.0.1
    port: 1080
    username: bob               # optional
    password: hunter2           # optional
    tls: false                  # optional; SOCKS5-over-TLS
    skip-cert-verify: false
    udp: false                  # ignored in M1; UDP deferred
```

Field reference — HTTP:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `server` | string | yes | — | Proxy server hostname or IP. |
| `port` | u16 | yes | — | Proxy server port. |
| `username` | string | no | — | Basic auth username. Both `username` and `password` must be set or neither. |
| `password` | string | no | — | Basic auth password. |
| `tls` | bool | no | `false` | Wrap TCP connection to proxy in TLS. |
| `skip-cert-verify` | bool | no | `false` | Skip TLS certificate verification. Only used when `tls: true`. |
| `headers` | map[str]str | no | `{}` | Extra headers injected into the CONNECT request. |

**Note:** `headers:` entries are injected into the CONNECT request only. After the tunnel is established, the payload is opaque bytes — there is no mechanism to inject headers into tunnelled HTTP traffic.

Field reference — SOCKS5:

| Field | Type | Required | Default | Meaning |
|-------|------|:-------:|---------|---------|
| `server` | string | yes | — | SOCKS5 server hostname or IP. |
| `port` | u16 | yes | — | SOCKS5 server port. |
| `username` | string | no | — | Username for auth method 0x02 (USERNAME/PASSWORD). |
| `password` | string | no | — | Password. |
| `tls` | bool | no | `false` | SOCKS5-over-TLS (uncommon but supported upstream). |
| `skip-cert-verify` | bool | no | `false` | Skip TLS cert verify. Only used when `tls: true`. |
| `udp` | bool | no | `false` | Accepted and ignored in M1 (UDP deferred). Warn-once at parse time. |

**Divergences from upstream** (classified per
[ADR-0002](../adr/0002-upstream-divergence-policy.md)):

| # | Case | Class | Rationale |
|---|------|:-----:|-----------|
| 1 | SOCKS5 UDP ASSOCIATE — upstream supports | B | Deferred to M1.x. `udp: true` is accepted and ignored with a warn-once. `dial_udp()` returns `UdpNotSupported`. |
| 2 | HTTP auth schemes other than Basic — upstream supports Digest | B | M1 supports Basic only. Unknown auth-required response from proxy → `Err(ProxyAuthFailed)`. |
| 3 | Both `username` and `password` must be set — upstream allows password-only | A | If only one of `username`/`password` is set, hard parse error. An orphaned credential is almost certainly a config mistake. |

## Internal design

### HTTP CONNECT handshake

```
1. dial TCP to (server, port)
2. if tls: wrap with TlsTransport (SNI = server)
3. send: "CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n"
         [if username: "Proxy-Authorization: Basic {base64(user:pass)}\r\n"]
         [for (k,v) in headers: "{k}: {v}\r\n"]
         "\r\n"
4. read response line: must be "HTTP/1.x 2xx ..."
   — 407 Proxy Authentication Required → Err(ProxyAuthFailed)
   — other 4xx/5xx → Err(HttpConnectFailed(status_code))
5. drain headers (read until blank line)
6. return stream as Box<dyn ProxyConn>
```

`{host}` is `metadata.host` (domain name as received from the client,
not pre-resolved). If `metadata.dst_ip` is available and `metadata.host`
is empty, use the IP address string. This preserves domain name for
SNI and logging on the upstream proxy.

**Response parsing**: read until `\r\n` for the status line. Accept
both `HTTP/1.0` and `HTTP/1.1`. Extract status code as u16.

### SOCKS5 handshake

```
1. dial TCP to (server, port)
2. if tls: wrap with TlsTransport
3. version negotiation:
   send: [0x05, nmethods, methods...]
   — no auth configured: nmethods=1, methods=[0x00]
   — auth configured:    nmethods=2, methods=[0x00, 0x02]
   recv: [0x05, chosen_method]
   — chosen_method = 0xFF → Err(NoAcceptableMethod)
   — chosen_method = 0x00 → proceed without auth sub-negotiation (even if credentials configured; server chose no-auth)
4. if chosen_method = 0x02 (username/password):
   send: [0x01, ulen, user..., plen, pass...]
   recv: [0x01, status]  — status 0x00 = success, else Err(ProxyAuthFailed)
5. send request:
   [0x05, 0x01, 0x00, atyp, dst_addr..., dst_port_hi, dst_port_lo]
   atyp: 0x01 = IPv4 (4 bytes), 0x03 = domain (1-byte len + bytes),
         0x04 = IPv6 (16 bytes)
   — prefer domain name (atyp 0x03) if metadata.host is set;
     else IPv4/IPv6 based on metadata.dst_ip
6. recv response:
   [0x05, rep, 0x00, atyp, bnd_addr..., bnd_port_hi, bnd_port_lo]
   rep 0x00 = success; else Err(Socks5ConnectFailed(rep))
7. return stream as Box<dyn ProxyConn>
```

Bound address (bnd_addr, bnd_port) from the response is read and
discarded — we don't use it for TCP relay. This matches upstream.

### Struct shapes

```rust
// crates/meow-proxy/src/http_adapter.rs
pub struct HttpAdapter {
    name: String,
    server: String,
    port: u16,
    auth: Option<(String, String)>,   // (username, password)
    tls_config: Option<Arc<ClientConfig>>,
    extra_headers: Vec<(String, String)>,
    health: ProxyHealth,
}

// crates/meow-proxy/src/socks5_adapter.rs
pub struct Socks5Adapter {
    name: String,
    server: String,
    port: u16,
    auth: Option<(String, String)>,
    tls_config: Option<Arc<ClientConfig>>,
    health: ProxyHealth,
}
```

### Error types

Add to `MeowError` in `meow-common`:

```rust
MeowError::ProxyAuthFailed,          // 407 or SOCKS5 auth failure
MeowError::HttpConnectFailed(u16),   // non-2xx from HTTP CONNECT
MeowError::Socks5ConnectFailed(u8),  // non-zero rep from SOCKS5
MeowError::NoAcceptableMethod,       // SOCKS5 server returned 0xFF
```

Error log messages must include a protocol prefix so debugging is unambiguous: log `"http proxy auth failed"` (not generic `"auth failed"`) for HTTP 407, and `"socks5 auth failed"` for SOCKS5 auth rejection.

### `connect_over` on `HttpAdapter` and `Socks5Adapter`

The `connect_over` method (added by M1.B-1 VMess PR) must be implemented
on both adapters. It performs the same handshake as `dial_tcp` but over
the passed-in stream instead of a freshly-dialled TCP socket:

```rust
async fn connect_over(
    &self,
    stream: Box<dyn ProxyConn>,
    meta: &Metadata,
) -> Result<Box<dyn ProxyConn>> {
    // run HTTP CONNECT / SOCKS5 handshake on `stream`
    // return wrapped stream
}
// Note: connect_over runs the adapter's complete post-connect pipeline —
// including its own TLS layer when `tls: true` is configured. The passed
// stream terminates at this adapter's own server, so its TLS stack is part
// of the protocol, not double-wrapping. (An earlier revision skipped the
// TLS wrap here; that was a bug fixed in #574 — a `tls: true` node in a
// non-first relay position would send plaintext to a TLS endpoint.)
```

This enables using HTTP CONNECT or SOCKS5 as hops in a relay chain.

## Acceptance criteria

1. `type: http` proxy with no auth dials target through CONNECT tunnel.
2. `type: http` proxy with `username`/`password` sends Basic auth header.
3. Proxy returns 407 → `Err(ProxyAuthFailed)`.
4. Proxy returns 503 → `Err(HttpConnectFailed(503))`.
5. `type: socks5` proxy with no auth negotiates method 0x00 and connects.
6. `type: socks5` proxy with auth negotiates method 0x02, authenticates,
   and connects.
7. SOCKS5 server returns method 0xFF → `Err(NoAcceptableMethod)`.
8. SOCKS5 auth failure (status ≠ 0x00) → `Err(ProxyAuthFailed)`.
9. `udp: true` on SOCKS5 → warn-once at parse time; `dial_udp()` returns
   `Err(UdpNotSupported)`. Class B per ADR-0002.
10. Only `username` set (no `password`) → hard parse error. Class A.
11. `tls: true` → connection to proxy wrapped in TLS; SNI = `server` field.
12. `skip-cert-verify: true` → certificate not validated.
13. `connect_over` on both adapters works in a relay chain (unit test with mock stream).
14. `extra_headers` (HTTP) injected into CONNECT request.
15. Domain name (`atyp 0x03`) preferred over IP in SOCKS5 request when `metadata.host` is set.

## Test plan (starting point — qa owns final shape)

**Unit (`http_adapter.rs`):**

- `http_connect_no_auth_succeeds` — mock TCP server echoes 200; assert
  returned stream carries payload. Upstream: `adapter/outbound/http.go::DialContext`.
- `http_connect_basic_auth_header_sent` — mock server checks header; assert
  correct Base64. NOT md5 or digest.
- `http_connect_407_returns_proxy_auth_failed` — mock returns 407; assert
  `Err(ProxyAuthFailed)`. Class A per ADR-0002.
- `http_connect_503_returns_http_connect_failed` — mock returns 503; assert
  `Err(HttpConnectFailed(503))`. NOT panic, NOT timeout.
- `http_extra_headers_injected` — configure `headers.X-Foo: bar`; mock
  asserts header present in CONNECT request.
- `http_missing_password_hard_errors_at_parse` — `username: alice` with no
  `password` → parse error. Class A per ADR-0002.

**Unit (`socks5_adapter.rs`):**

- `socks5_no_auth_connects` — mock server: no-auth negotiation → CONNECT reply
  success → assert stream usable.
  Upstream: `adapter/outbound/socks5.go::DialContext`.
- `socks5_user_pass_auth_succeeds` — negotiate method 0x02, auth success.
- `socks5_no_acceptable_method_returns_error` — server returns 0xFF; assert
  `Err(NoAcceptableMethod)`. NOT retry. NOT fallback to no-auth.
- `socks5_server_chooses_no_auth_despite_creds_configured` — advertise both [0x00, 0x02]; mock server picks 0x00; assert connection proceeds WITHOUT auth sub-negotiation (no [0x01, ulen, ...] sent). NOT Err(NoAcceptableMethod). Upstream: socks5.go::handshake; server may prefer no-auth even when offered user/pass.
- `socks5_auth_failure_returns_proxy_auth_failed` — auth status ≠ 0x00.
- `socks5_connect_failure_returns_socks5_connect_failed` — rep=0x02 (CONN_NOT_ALLOWED).
- `socks5_domain_name_preferred_over_ip` — metadata has both host and dst_ip;
  assert wire frame uses atyp 0x03 (domain), NOT atyp 0x01 (IPv4).
  NOT IP-only dial when domain is available.
- `socks5_ipv4_used_when_no_hostname` — metadata has dst_ip only; assert
  atyp 0x01 frame.
- `socks5_udp_true_warns_and_returns_unsupported` — `udp: true` config warns;
  `dial_udp()` → `Err(UdpNotSupported)`. Class B per ADR-0002.
- `socks5_connect_over_in_relay_chain` — pass mock ProxyConn stream;
  assert handshake runs over it and payload arrives. NOT fresh TCP connect.

**Unit (config parser):**

- `parse_http_proxy_minimal` — server + port only, no auth.
- `parse_http_proxy_full` — all fields including headers.
- `parse_socks5_proxy_no_auth` — minimal.
- `parse_socks5_proxy_with_auth` — username + password.
- `parse_orphan_username_hard_errors` — username without password → error.
  Class A per ADR-0002. Upstream: undefined behaviour.

## Implementation checklist (engineer handoff)

**Sequencing: M1.A-1 must land (TLS transport) before `tls: true` is wired.
`connect_over` requires M1.B-1 (VMess) to have added the trait method.**

- [ ] Add `MeowError::ProxyAuthFailed`, `HttpConnectFailed(u16)`,
      `Socks5ConnectFailed(u8)`, `NoAcceptableMethod` to `meow-common`.
- [ ] Implement `http_adapter.rs`. Comment cites upstream:
      `// upstream: adapter/outbound/http.go`.
- [ ] Implement `socks5_adapter.rs`. Comment cites upstream:
      `// upstream: adapter/outbound/socks5.go`.
- [ ] Wire `parse_proxy` in `meow-config` for `type: "http"` and `type: "socks5"`.
- [ ] Update `docs/roadmap.md` M1.B-3 and M1.B-4 rows with merged PR link.
