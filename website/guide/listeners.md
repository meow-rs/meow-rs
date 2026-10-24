# Listeners

Listeners are meow-rs's inbounds — the local ports it accepts traffic on. There are two
ways to declare them: the shorthand top-level ports, and the explicit `listeners` array.

## Shorthand ports

The quickest setup. Each opens one listener bound to `bind-address`:

| Key | Listener |
| --- | --- |
| `mixed-port` | Mixed HTTP + SOCKS5 (auto-detects from the first byte) |
| `port` | HTTP proxy only |
| `socks-port` | SOCKS5 only |
| `tproxy-port` | Transparent proxy (binds `127.0.0.1`) |

```yaml
mixed-port: 7890
```

`mixed-port` is usually all you need — it serves both HTTP and SOCKS5 clients on one port.

Setting a shorthand port to `0` disables that inbound (mihomo-compatible) — it does
**not** bind an ephemeral port. Ephemeral ports are a `listeners`-array feature.

## The `listeners` array

For multiple instances, per-listener binds, or per-listener limits, declare them
explicitly. Shorthand ports and the array are merged at load time.

```yaml
listeners:
  - name: web
    type: http
    port: 7890
    listen: 0.0.0.0
  - name: sock
    type: socks5
    port: 7891
  - name: gateway
    type: tproxy
    port: 7893
    listen: 0.0.0.0
    max-connections: 1000
```

| Field | Type | Required | Default | Notes |
| --- | --- | --- | --- | --- |
| `name` | string | ✓ | — | Unique; appears in logs, the API, and `IN-NAME` rules |
| `type` | string | ✓ | — | `mixed` · `http` · `socks5` · `tproxy` · `shadowsocks` |
| `port` | u16 | | — | Unique across listeners; omit or `0` to let the OS assign an ephemeral port |
| `listen` | string | | per type | Bind IP literal, or `host:port` (e.g. `127.0.0.1:0`) |
| `tproxy-sni` | bool | | global | (tproxy) deprecated SNI shorthand — prefer [`sniffer`](./sniffer) |
| `firewall` | bool | | `true` | (tproxy) `false` = external firewall management — no nft/pfctl calls, no cleanup; see [Transparent Proxy](./transparent-proxy) |
| `udp` | bool | | `false` | (tproxy, Linux/IPv4 only) UDP TPROXY on the same port; requires `firewall: false`; see [Transparent Proxy](./transparent-proxy) |
| `udp-timeout` | secs | | `60` | (tproxy) UDP flow idle timeout; `0` is an error |
| `max-connections` | usize | | global | Per-listener concurrency cap; `0` = unlimited |

`listen` defaults to `127.0.0.1` for `tproxy` and to the global `bind-address` otherwise.

### Ephemeral ports

A listener with port `0` (via `port: 0`, an omitted `port`, or `listen: 127.0.0.1:0`)
binds an OS-assigned ephemeral port at startup. Discover the assigned port from the
startup log line (`Mixed listener 'auto' on 127.0.0.1:49321 …`) or from
[`GET /listeners`](#inspecting-listeners) on the REST API, which reports the actual
bound port.
Giving both `listen: host:port` and `port` with different values is a load-time error.

```yaml
listeners:
  - name: auto
    type: mixed
    listen: 127.0.0.1:0
```

::: warning Duplicates are fatal
Duplicate listener **ports** or **names** are a hard load-time error (unlike upstream,
which may accept them silently). Multiple port-`0` listeners are fine — each gets its
own OS-assigned port.
:::

## Listener types

- **`mixed`** — HTTP and SOCKS5 on one port; supports inbound auth and the sniffer.
- **`http`** — HTTP CONNECT proxy.
- **`socks5`** — SOCKS5 proxy; supports inbound auth.
- **`tproxy`** — firewall transparent proxy (Linux / experimental macOS); see [Transparent Proxy](./transparent-proxy).
- **`shadowsocks`** — Shadowsocks server inbound; its `udp` field gates the
  SS UDP relay (default `true`) and is unrelated to tproxy's `udp`.
  Included in the release binaries (the `listener-shadowsocks` cargo
  feature is in `full`, not in `minimal` — see
  [ss-listener.md](https://github.com/meow-rs/meow-rs/blob/main/docs/ss-listener.md));
  a build without it fails `-t`/startup rather than silently skipping the
  port.
- **`tun:`** (top-level, not in this array) — L3 TUN inbound. On Windows this is a
  Wintun adapter and is the transparent-proxy path. See [Transparent Proxy](./transparent-proxy).

## Inbound authentication

HTTP and SOCKS5 inbounds can require credentials. Define them at the top level (they apply
to all auth-capable listeners):

```yaml
authentication:
  - "alice:secret"
  - "bob:hunter2"
skip-auth-prefixes:
  - 127.0.0.1/8
  - 192.168.1.0/24
```

Connections from `skip-auth-prefixes` bypass auth. The authenticated username is available
to the `IN-USER` rule. See [Authentication](./authentication) for details.

## Routing by inbound

Three rule types let you route based on *where a connection came in*:

- `IN-PORT` — the listener port.
- `IN-NAME` — the listener `name`.
- `IN-TYPE` — `HTTP` / `HTTPS` / `SOCKS5` / `TPROXY` / `INNER`.

```yaml
rules:
  - IN-NAME,gateway,Proxy
  - IN-TYPE,SOCKS5,DIRECT
```

## Inspecting listeners

`GET /listeners` returns the active listeners with their name, type, port, and bind
address; `tproxy` entries additionally report `firewall` (whether meow manages
the redirect rules or they are externally owned). For [ephemeral listeners](#ephemeral-ports)
the reported port is the actual OS-assigned one, not the configured `0`. See the
[REST API reference](../reference/rest-api).
