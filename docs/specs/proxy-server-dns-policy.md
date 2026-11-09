# Proxy-server DNS policy

`dns.proxy-server-nameserver-policy` uses the same ordered map and domain,
wildcard, geosite and rule-set keys as `nameserver-policy`, but applies only to
the dedicated node resolver. This follows the [mihomo configuration field](https://wiki.metacubex.one/en/config/dns/#proxy-server-nameserver-policy).
It is inactive unless DNS is enabled and `proxy-server-nameserver` is nonempty.
Ordinary queries retain their own policy; node queries always use real-address
resolution, even when the main resolver uses FakeIP.

```yaml
dns:
  enable: true
  nameserver: [1.1.1.1]
  proxy-server-nameserver: [9.9.9.9]
  nameserver-policy-exclusive: true
  proxy-server-nameserver-policy:
    '+.nodes.example': [192.0.2.53]
```

The addresses and domains above are examples, not a deployable configuration.
Unmatched node domains use `proxy-server-nameserver`. With the existing
`nameserver-policy-exclusive: true`, a matched policy failure is terminal; it
never falls through to the node default pool or the ordinary resolver. The
flag remains off by default, consistent with meow's existing policy behavior.

Policy reordering is a DNS input change. Proxy references also force a resolver
rebuild when the proxy registry changes; rule-set matchers bind to the candidate
provider generation. DNS feature checks, domain-key validation and geosite
discovery use the same machinery as the ordinary policy. The global `prefer-h3`
does **not** rewrite node-policy `https://` entries — proxy hostname resolution
is latency-sensitive and a silent H3 attempt would just time out where QUIC is
firewalled; an explicit `?h3=` entry still works and is still
capability-gated.

## Independent bootstrap requirements

A policy that decides how to resolve a node cannot first require that same node
to resolve or download its own policy dependencies. Following ADR-0002 Class A,
these new configurations fail explicitly rather than silently depending on a
warm cache or the system resolver:

- A policy nameserver tagged with a proxy must name a known, unchained node
  whose server is an IP literal. Hostname nodes, groups and chained nodes are
  conservatively rejected: their endpoint dependency is not independently
  established. Use an untagged nameserver or an unchained IP-literal node.
- A `rule-set:` condition must use an inline or file provider. HTTP providers
  are rejected before provider fetch at startup and rebuild, even if cached or
  initially IP-literal/DIRECT: redirects and subsequent refreshes can introduce
  hostname or proxy dependencies. Materialize an independently maintained file
  or use inline rules until independent remote bootstrap is supported.

These restrictions apply to the new node policy, not to ordinary policies or
the legacy base `proxy-server-nameserver` list. Existing base-list diagnostics
and runtime resolver re-entry fences remain unchanged. This change does not
introduce a new resolver owner or claim to redesign global geodata bootstrap.
