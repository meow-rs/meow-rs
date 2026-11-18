# Authentication

There are two independent kinds of authentication in meow-rs: **inbound** auth on the
HTTP/SOCKS5 listeners, and **API** auth on the REST controller.

## Inbound proxy auth

Require credentials from clients connecting to the HTTP/SOCKS5 inbounds. Define
`user:pass` pairs at the top level; they apply to all auth-capable listeners.

```yaml
authentication:
  - "alice:secret"
  - "bob:hunter2"
skip-auth-prefixes:
  - 127.0.0.1/8
  - 192.168.1.0/24
```

| Field | Type | Default | Notes |
| --- | --- | --- | --- |
| `authentication` | list | `[]` | `username:password` credentials |
| `skip-auth-prefixes` | list | `[]` | Source CIDRs exempt from auth |

- Connections from a `skip-auth-prefixes` range skip the credential check — handy for
  trusted LANs and loopback.
- The authenticated username is exposed to the [`IN-USER`](./rules#inbound-network-rules)
  rule, so you can route per user:

  ```yaml
  rules:
    - IN-USER,alice,Proxy
    - IN-USER,bob,DIRECT
  ```

## REST API auth

The [REST API](../reference/rest-api) is protected by a single shared secret.
Applying a change to that secret requires a restart.

```yaml
external-controller: 127.0.0.1:9090
secret: "a-long-random-string"
```

- An empty or absent `secret` leaves the controller unauthenticated. Use this mode only
  on a trusted loopback bind. Connect by IP address or `localhost`. Browser API and
  WebSocket requests must come from the controller's own origin.
- REST requests authenticate with a bearer header: `Authorization: Bearer <secret>`.
- WebSocket endpoints (`/logs`, `/traffic`, `/memory`) accept either the bearer header or
  a `?token=<secret>` query parameter.
- The secret is compared in constant time to avoid timing leaks.

::: warning Exposing the controller
If you bind `external-controller` to a non-loopback address, always set a strong `secret`.
Set a secret for cross-origin dashboards and reverse proxies serving the controller
over a custom hostname. With a secret, CORS allows any origin and API requests still
require the token.
:::
