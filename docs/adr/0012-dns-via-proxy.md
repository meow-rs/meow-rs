# ADR 0012: Route DNS clients through a proxy adapter (`#PROXY` nameserver suffix)

- **Status:** Proposed
- **Date:** 2026-05-19
- **Author:** Claude (on behalf of @madeye)
- **Related:** issue #67, PR #88 (per-proxy DNS for `type: direct`)

## Context

Issue #67 has two parts:

1. **"When the rule engine matches a request to a proxy, route the DNS lookup through that proxy."**
2. **"Allow configuring a dedicated DNS server for a specific proxy or proxy group."**

Part 2 is largely covered today:

- For non-direct outbounds (SS / Trojan / VLESS / HTTP), the **hostname is forwarded to the remote** (`shadowsocks_adapter.rs:295`, `http_adapter.rs:117`, etc.). The remote server performs the DNS lookup, so per-proxy DNS is effectively the remote's resolver.
- For direct outbounds, PR #88 added a `dns:` field on `type: direct` proxies. The `DirectAdapter` resolves hostnames against the configured servers via an injected `Resolver`.
- `nameserver-policy` already supports per-domain routing of DNS queries to specific upstreams.

What is **not** covered is the deeper "DNS query routed *through* a proxy adapter" pattern. Upstream Clash / mihomo support a `1.1.1.1#PROXY-NAME` syntax on `nameserver:` entries, where the DNS exchange itself is tunneled through the named proxy's TCP/UDP relay. This lets a user say "ask Google DNS, but go through my Japan exit," which is the classic case for resolving geo-fenced records correctly.

This ADR proposes the syntax, the loop-prevention rules, and the layering for implementing that feature on top of the current `DnsClient` / `Resolver` design.

## Decision

### Syntax

Extend `NameServerUrl` (`crates/meow-dns/src/upstream.rs`) so each variant carries an optional `proxy: Option<String>`:

```rust
NameServerUrl::Udp { addr, port, proxy: Option<String> }
NameServerUrl::Tcp { addr, port, proxy: Option<String> }
NameServerUrl::Tls { addr, port, sni, proxy: Option<String> }
NameServerUrl::Https { addr, port, path, sni, proxy: Option<String> }
```

Surface syntax:

| YAML string | Effect |
|---|---|
| `1.1.1.1` / `1.1.1.1:53` | Plain UDP, global resolver (unchanged) |
| `1.1.1.1#PROXY-JP` | Plain UDP, **but tunneled over PROXY-JP** |
| `tcp://1.1.1.1:53#PROXY-JP` | TCP DNS over PROXY-JP |
| `tls://1.1.1.1#dns.google` | DoT, current SNI fragment semantics (no proxy) |
| `tls://1.1.1.1#dns.google?proxy=PROXY-JP` | DoT over PROXY-JP (new — query-string disambiguator for TLS/HTTPS) |
| `https://1.1.1.1/dns-query#cloudflare-dns.com?proxy=PROXY-JP` | DoH over PROXY-JP |

The collision with SNI on `tls://` / `https://` URLs (which already use `#` for SNI) is resolved with a **query-string parameter** `?proxy=NAME` rather than a second fragment. This keeps the existing SNI semantics intact and avoids ambiguity.

For plain UDP/TCP nameservers (no SNI), the `#PROXY-NAME` suffix reuses the existing fragment slot, matching upstream Clash syntax.

### Loop prevention

DNS-over-proxy creates one hard loop hazard:

> Proxy `A` is configured with `dns: 1.1.1.1#PROXY-A`. To dial proxy A, the system needs to resolve A's server hostname `ss.example.com`. If that lookup is routed through PROXY-A, we re-enter `A.dial_tcp()` before A is dialable → infinite recursion.

**Mitigation rules** (enforced at config-parse time, hard error per ADR-0002 Class A — silent breakage in DNS is a privacy failure):

1. **Proxy-server hostnames must never resolve through a `#PROXY` client.** When the resolver dials a proxy adapter, it must use a *bootstrap* resolver that has no `#PROXY` entries. This is the same bootstrap path that already resolves `dns.google` for an encrypted upstream today (`resolver.rs:354–382`).

   *Implemented as a runtime fence rather than a retained bootstrap pool.* Since proxy-server hostnames now resolve through the `meow_common::HostResolver` hook (i.e. through this resolver) on every platform, the cycle is detected where it forms: `resolve_addrs` marks its task while the hook runs, and a dial made under that mark — which is exactly a `#PROXY` upstream dialing its own proxy — is answered by `Resolver::resolve_ips_local` (`hosts:` trie + DNS cache, never an upstream query), falling through to the system resolver when nothing is known. This holds the invariant without keeping the throwaway bootstrap clients alive past construction, and without which the resolver's single-flight `inflight` entry would make the inner lookup wait on the outer one.
2. **Direct cycle detection**: if proxy `A` declares `dns: <anything>#A`, reject the config at load.
3. **Indirect cycles** (A→B→A) are detected by walking the proxy `dns:` graph at config load. A cycle is a Class A error.

### Architecture

```
Tunnel → match_rules → Proxy A → A.dial_tcp(metadata)        (data path)
                                  ^
                                  └── DnsClient(proxy=A).exchange()
                                          ^
                                          └── used by Resolver when YAML has `#A`
```

The `SocketFactory` indirection in `client.rs:34` returns concrete `TcpStream` / `UdpSocket`. We **do not** generalize the factory; instead `DnsClient` holds an optional `Arc<dyn Proxy>` and branches inside each exchange function:

```rust
async fn tcp_exchange(addr: SocketAddr, wire: &[u8], proxy: Option<&Arc<dyn Proxy>>) -> ... {
    let mut stream: Box<dyn AsyncRead + AsyncWrite + Unpin + Send> = match proxy {
        Some(p) => Box::new(p.dial_tcp(&dns_metadata(addr)).await?),
        None => Box::new(factory().connect_tcp(addr).await?),
    };
    write_lp(&mut stream, wire).await?;
    read_lp(&mut stream).await
}
```

For UDP-via-proxy, fall through to TCP DNS automatically (most proxies don't relay arbitrary UDP). Document this in the config docs — users wanting true UDP-over-proxy must set `udp: true` on the proxy AND use `tcp://` URL form (the TCP fallback is the safer default).

For DoT/DoH, layer `tokio_rustls` / HTTP/1.1 over the `Box<dyn AsyncRead+AsyncWrite>` exactly as today — the existing TLS connector is generic over `IO: AsyncRead + AsyncWrite + Unpin`.

### Proxy registry threading

`Resolver` construction (`new_with_bootstrap`) accepts a new `proxy_registry: Arc<HashMap<String, Arc<dyn Proxy>>>` parameter. The resolver resolves `#PROXY-NAME` strings to `Arc<dyn Proxy>` at construction time, failing fast (Class A) if the name is unknown — silent fallback to the global resolver would leak the query.

In `meow-config::build_config`, proxies are constructed before the resolver, so the registry handoff is straightforward.

*Addendum (issue #533):* a `dialer-proxy`-chained adapter resolves its front hop
through a registry cell owned by the route-table generation that built it. A
retained resolver therefore must not outlive that generation — when either the
old or candidate config contains `#name` nameserver refs, `reconcile_dns_config`
forces a resolver rebuild on every commit, and the commit paths install the new
resolver before swapping the route table so no query observes a dead cell.

### What this ADR does NOT cover

- **UDP-native DNS through proxy** when the proxy supports UDP. V1 routes all `#PROXY` queries over TCP. UDP-over-proxy is an optimization that can land later behind a `udp-dns: true` flag.
- **`fakeip` routing through proxy** — fake-IP synthesis happens *before* the proxy is chosen, so the question is meaningless for fakeip mode.
- **Per-rule-set DNS routing** (resolve domains in ruleset X via proxy Y). That's `nameserver-policy` territory and is already partially supported.

## Consequences

- One new field per `NameServerUrl` variant, one new `Resolver` constructor parameter, one new optional field on `DnsClient`. The default code path (no `#PROXY`) is unchanged.
- Two new Class A hard-errors at config load (unknown `#PROXY` name, cycle in `dns:` graph). Both are documented in the config reference.
- Bootstrap DNS (used to resolve proxy server hostnames) is explicitly a `#PROXY`-free resolver, breaking the loop.
- Tests need a mock `Proxy` that records the DNS message it was asked to relay; this is straightforward (`crates/meow-dns/tests/proxy_routed_dns_test.rs`).

## Implementation order

1. Extend `NameServerUrl` enum + parser. Behind a temporary `dns-via-proxy` feature flag.
2. Add `with_proxy` builder on `DnsClient`. Refactor exchange functions to take an optional proxy.
3. Thread proxy registry into `Resolver::new_with_bootstrap`.
4. Wire config-load: build proxies first, then resolver, then validate `#PROXY` references.
5. Cycle detection on the `dns:` graph.
6. Integration test with a stub `Proxy` adapter.
7. Remove feature flag; update config reference docs.
