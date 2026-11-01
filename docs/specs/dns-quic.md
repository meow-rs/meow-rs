# Spec: DNS over QUIC and DoH over HTTP/3

Status: Implemented on `feat/dns-quic` (behind the `dns-quic` feature)
Tracks: the two DNS transports mihomo has and meow-rs did not
Upstream reference: `dns/doq.go` (RFC 9250 client), `dns/doh.go` (`PreferH3`,
`&h3=true`, the h3 transport), `config/config.go::parseNameServer` (`quic://`),
`dns/util.go::transform`.
Depends on: `meow-dns`'s `encrypted` feature (shared certificate decision and the
HTTP/1.1 DoH fallback path).

## Motivation

meow-rs parsed `quic://` as a hard error ("roadmap M1.E-6") and had no HTTP/3
DoH at all, so a mihomo config that uses either transport could not be migrated
without rewriting the `dns:` block:

```yaml
dns:
  nameserver:
    - quic://dns.adguard.com          # DoQ
    - https://1.1.1.1/dns-query       # mihomo `prefer-h3: true` upgrades this
```

Both transports are QUIC, so they share one implementation surface: a connection
driver, one BoringSSL-backed `quiche::Config`, and one socket chokepoint.

## Scope

In scope:

1. `quic://host[:port][#sni]` nameserver entries, RFC 9250 DoQ, default port 853.
2. `dns.prefer-h3` (mihomo key) — every `https://` entry prefers HTTP/3.
3. Per-entry `?h3=true|prefer|false` on `https://` entries.
- `?proxy=NAME` on `quic://` / `?h3=` entries (datagram through the adapter), with an
  IP-literal server address — see the divergence table.
5. One connection per upstream, multiplexed, re-dialed transparently.

Out of scope (unchanged by this work): DoQ/DoH3 as *server* listeners (meow-rs is
a client kernel), ECH-over-QUIC-specific tuning, 0-RTT resumption, connection
migration.

## Design

### One driver per upstream

`QuicUpstream` owns a background task that holds the socket and the
`quiche::Connection`. Callers send `(query bytes, oneshot reply)` over an
unbounded channel, so:

- a burst of A/AAAA lookups multiplexes over a single handshake;
- an idle timeout, a peer close or `reset_connections()` ends the connection and
  the next query dials a fresh one — the message channel survives, so callers
  never see the reconnect;
- every query still in flight (or still queued behind a failed handshake) is
  failed with the *real* reason (`Tls`, `Io`, …), because the caller's retry and
  the DoH3 fallback decision both depend on that classification.

### DoQ wire format

Per RFC 9250 §4.2: one client-initiated bidirectional stream per query, the DNS
message preceded by a two-octet length (the same framing as DNS over TCP), and
the DNS transaction ID set to `0`. The caller's ID is restored before the shared
`validate_response` runs, so ID/opcode/question validation stays in one place.

### DoH3 and `prefer-h3`

RFC 8484 over HTTP/3: one `POST <path>` per query with `application/dns-message`
both ways; a non-200 `:status` is a protocol error. `prefer-h3` means *prefer*,
not *require*:

- the h3 attempt runs under half the per-query timeout, so a hung handshake
  cannot consume the budget the fallback needs;
- on failure the exchange retries over the client's own HTTP/1.1 DoH path (same
  proxy tag, roots, session pool);
- the failed handshake parks h3 for 10 minutes, so a server without HTTP/3 pays
  one failed handshake instead of one per query.

`?h3=true` keeps mihomo's per-entry meaning (HTTP/3 only, no fallback);
`?h3=prefer` and `?h3=false` are meow-rs spellings for per-entry opt-in/opt-out.

### Certificate handling

`quiche::Config::with_boring_ssl_ctx_builder` with an `SslContextBuilder` seeded
from the same `webpki-root-certs` bundle and the same
`meow_transport::tls::distrust::verify_callback` the DoT/DoH path uses. quiche
installs the SNI as the verify hostname, so hostname validation is unchanged.
Nothing here links a second crypto library: quiche runs on the vendored
BoringSSL the workspace already pins.

### Feature gating

`meow-dns/quic-dns` (implied by `meow-app`'s `dns-quic`, which is part of `full`
and absent from `minimal` for the ADR-0007 size caps). Without it:

- `quic://` is a hard parse error naming the feature;
- `?h3=` / `prefer-h3` is a hard *load* error from `meow-config` (Class A per
  ADR-0002) — never a silent downgrade to HTTP/1.1.

## Divergences (ADR-0002)

| Config | mihomo | meow-rs | Class |
| --- | --- | --- | --- |
| `quic://` without a build that has it | n/a (Go always has DoQ) | Hard error naming `dns-quic` | A |
| `?h3=true` | HTTP/3 only | Same | — |
| `prefer-h3` | Allowed alongside h1/h2 | Prefer, with a 10-minute park after a failed handshake | B |
| `?h3=prefer` / `?h3=false` | Not a key | Per-entry opt-in / opt-out of `prefer-h3` | — |
| `#h3=true` (mihomo writes params in the fragment) | Parameter | Hard error: `#` is SNI in meow-rs; the fix is `?h3=true` | A |
| `?proxy=` on a QUIC entry whose server is a hostname | Works (the adapter resolves it) | Hard load error: quiche must know the peer before the handshake, and a proxied hostname hides it — a hung query otherwise | A |

## Testing

- `crates/meow-dns/tests/quic_dns_integration.rs` — an in-process `quiche` DoQ
  server and an in-process HTTP/3 DoH server (self-signed rcgen chain trusted
  through the debug-build `with_tls_additional_roots` hook). Covers: DoQ framing
  and ID-0 on the wire, connection reuse, redial after `reset_connections`,
  NXDOMAIN relay, certificate rejection, the h3 POST shape, the HTTP/1.1
  fallback with h3 parked, and force-only mode reporting the QUIC failure.
- `crates/meow-dns/src/upstream.rs` — `?h3=` parsing/validation, `quic://`
  parsing with SNI and proxy tags, Display round-trip, feature-gated rejection.
- `crates/meow-config` — `prefer-h3` rewriting (URL strings and
  `nameserver-policy` values) and the feature-gate load error.
- `crates/meow-config/tests/config_test.rs` — end-to-end: labels carry
  `h3=prefer`, an explicit `?h3=false` wins, and a build without the feature
  refuses the config.
