# Setting up meow as a transparent-proxy gateway

Last updated: 2026-06-25. Tracks `meow` 0.15.x.
Owner: ops. Audience: operators turning a Linux box (router, Raspberry Pi,
mini-PC) into a LAN gateway that transparently proxies other devices' traffic.

This guide builds a **gateway**: a Linux host that other devices on the LAN use
as their default route, so their traffic is intercepted and routed by meow's
rules without any per-device proxy configuration.

If you only want to transparently proxy traffic originating **on the meow host
itself** (not forward other devices), most of this is unnecessary — set
`tproxy-port` and meow's built-in firewall handles it. The
[`scripts/tproxy-local-linux.sh`](../scripts/tproxy-local-linux.sh) /
[`scripts/tproxy-local-macos.sh`](../scripts/tproxy-local-macos.sh) wrappers run
meow that way (`up`/`down`/`status`) and confirm the auto-created firewall. Read
[How meow's transparent proxy works](#how-meows-transparent-proxy-works) and
[DNS mode](#dns-mode-fake-ip-vs-redir-host), then stop.

---

## How meow's transparent proxy works

Understand this before configuring — it explains every step below.

- **It accepts both `REDIRECT` and kernel TPROXY.** For redirected TCP, meow
  recovers the original destination with `getsockopt(SO_ORIGINAL_DST)`; a
  `listeners:` `type: tproxy` entry with `transparent: true` (Linux only,
  `firewall: false` required) instead accepts **real TCP TPROXY** — the
  accepted socket's local address is the original destination. UDP TPROXY is a
  separate Linux opt-in (`udp: true`): transparent UDP sockets receive
  forwarded datagrams steered by per-family mangle-prerouting `tproxy` rules,
  recover the original destination from the per-family original-destination
  control message, and reply from that original address and port. The recipe
  below uses TCP `REDIRECT` unless you opt into `transparent: true`. The
  OpenWrt package's `gateway.sh` ([openwrt.md](openwrt.md)) implements a
  TPROXY variant: mangle-prerouting `tproxy` rules plus fwmark policy routes
  to `local … dev lo`.
- **The built-in firewall is `output`-chain only.** When you set a tproxy
  listener with managed firewall (the default), meow auto-creates an nftables
  table (`inet meow_tproxy_<pid>_<seq>` — unique per listener instance, swept
  at the next startup when its owning pid is dead or was recycled by a
  non-meow process) with a `nat` hook on `output` that redirects the
  **host's own** outbound TCP to the listener. It is torn down automatically
  on shutdown (RAII guard). It includes loop-avoidance: a `meta mark` bypass
  for `DIRECT`-marked sockets (`routing-mark`), loopback bypass, and per-IP
  bypass for your upstream proxy servers.
- **It does NOT touch forwarded traffic.** Traffic from *other* LAN devices
  passes through the `prerouting`/`forward` path, which meow's built-in table
  never hooks. **You must add those rules yourself** (this guide's `meow_gateway`
  table).
- **UDP is off by default.** QUIC (UDP/443) and other UDP from the LAN are
  not intercepted unless you opt in with `udp: true` (see below). In
  practice you suppress QUIC at the DNS layer (see fake-ip below) so
  clients fall back to TCP.

### Why the listener must NOT bind to loopback

For **forwarded** traffic, a `prerouting` `REDIRECT` rewrites the destination to
the **inbound interface's primary IP** (e.g. `192.168.1.1`), *not* `127.0.0.1`.
So the listener has to be reachable on a non-loopback address.

The convenient top-level `tproxy-port:` key **hard-binds `127.0.0.1`**, which
only catches the `output`-chain redirect (the host's own traffic) — forwarded
connections land on `<LAN_IP>:<port>` and get refused. **For a gateway you must
declare the listener explicitly with a non-loopback `listen`:**

```yaml
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'        # dual-stack; or 0.0.0.0 for v4-only. NOT 127.0.0.1.
    port: 7893
```

(Do not also set the top-level `tproxy-port` — that would create a second,
loopback-bound listener on a different port.)

### `firewall: false` — fully external rule management

If you want to own **all** the firewall state — including the output chain and
the loop-prevention bypasses meow normally installs — set `firewall: false` on
the named listener (issue #563):

```yaml
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'
    port: 7893
    firewall: false   # meow never invokes nft/pfctl for this listener
```

Under external management meow installs nothing, probes nothing, and removes
nothing on exit — including the `meta mark` bypass and upstream proxy-IP bypass
list (they are not even collected). You must reproduce every rule the managed
table carried, or the loop-prevention story breaks:

1. **`meta mark` bypass** — `meta mark <routing-mark> accept` so meow's own
   outbound (which keeps setting `SO_MARK` via `routing-mark` regardless of
   firewall mode) is not re-captured. Keep `routing-mark` configured; a
   deployer bypass that matches nothing still loops.
2. **Loopback exemption** — `ip daddr 127.0.0.0/8 accept` (+ `ip6 daddr ::1
   accept`) or the host's own loopback TCP is redirected into the listener.
3. **Upstream proxy-IP bypasses** — one `ip daddr <proxy-server> accept` per
   upstream, or meow's connections to your proxies re-enter the listener.
4. **The catch-all redirect** — `tcp dport 1-65535 redirect to :<port>` last.

`tests/tproxy-docker/meow-tproxy-ext.yaml` + `guest-init.sh` phase 2 contain a
complete reference table. You also own the boot-ordering/fail-open story:
rules pointing at the listener port before meow binds will refuse or pass
through depending on your ruleset. Use a fixed port — `port: 0` is only
viable if you read the bound port back via `GET /listeners` (requires
`external-controller`) or the startup log, and install rules afterwards.
Changes need a restart; there is no listener hot-reload.

The `tproxy-port:` shorthand always keeps the managed firewall — a top-level
`firewall:` key does not exist (it warns and is ignored), so external
management requires declaring the listener under `listeners:` as above.

This is the mode to reach for when nftables is unavailable, when another
privileged service (or iptables) owns redirect policy, or when you want custom
output-chain behaviour the built-in table doesn't express.

### `type: redir` / `redir-port` — REDIRECT-only, deployer-owned rules

mihomo's `redir-port` inbound is a narrower form of the above: REDIRECT for
TCP, nothing else, and meow owns no rules. The top-level `redir-port:` key is
a shorthand for a `listeners:` `type: redir` entry — `firewall`, `udp`,
`udp-timeout`, `transparent`, and the Shadowsocks keys all warn and are
ignored on it:

```yaml
redir-port: 7893
# or equivalently:
listeners:
  - name: redir-gw
    type: redir
    listen: '0.0.0.0'   # non-loopback — the prerouting REDIRECT rewrites to
    port: 7893          # the inbound interface's address, not 127.0.0.1
```

Same obligations as `firewall: false`: you own the `meta mark`
(`routing-mark`) exemption, the loopback exemption, and the catch-all
`redirect` — plus UDP is not an option.

### `transparent: true` — real TCP TPROXY (Linux only)

A `type: tproxy` entry with `transparent: true` switches TCP from REDIRECT
to real kernel TPROXY: the listener socket is created with
`IP_TRANSPARENT`/`IPV6_TRANSPARENT` (needs `CAP_NET_ADMIN`) and the accepted
connection's *local* address is the original destination — no
`SO_ORIGINAL_DST` call. It requires `firewall: false` (the deployer owns the
mangle `tproxy` rule and the fwmark→`local` policy route) and errors at
startup on a non-Linux build. `transparent: false` — the default — keeps the
REDIRECT semantic for backward compatibility, and the `tproxy-port` /
`redir-port` shorthands never set it.

```yaml
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'
    port: 7893
    firewall: false
    transparent: true
    udp: true            # optional, independent: UDP TPROXY on the same port
```

`transparent` selects the TCP mode only; it is not a prerequisite for
`udp: true`. The combination above is valid: with `udp: true`, `listen: '::'`
binds one UDP socket per family on the same port.

### `udp: true` — UDP TPROXY on the same port (Linux only)

The named listener can additionally serve **UDP** via TPROXY on the same port
(issues #564/#1017). Scope in this release:

- **Linux only.** A non-Linux build rejects `udp: true` at startup.
- **External firewall required.** `udp: true` must be combined with
  `firewall: false`; meow never installs UDP TPROXY rules or policy routing —
  the deployer owns all of it, and nothing is removed on exit.
- **LAN forwarding only.** UDP TPROXY intercepts on the `prerouting` hook;
  the host's *own* UDP traffic (`output`) is not captured — same restriction
  as every TPROXY deployment.
- UDP port 53 follows the normal routing rules — there is no implicit DNS
  hijack. Point your rules at the meow DNS listener explicitly if you want
  that.

The `listen` address selects the UDP family coverage:

| `listen` spelling | UDP sockets bound |
|---|---|
| `0.0.0.0` or a specific IPv4 address | one IPv4 socket |
| `::` | one V6ONLY IPv6 socket plus one IPv4 wildcard socket, same port |
| a specific unscoped, non-link-local IPv6 address | one IPv6 socket |
| IPv4-mapped IPv6, scoped (`%zone`), or link-local (`fe80::/10`) | config error |

The dual-stack pair is atomic: if either family cannot bind, the listener
fails rather than silently publishing half of it. Use a fixed port in normal
deployments — external rules need the port before meow starts.

```yaml
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'         # UDP: dual-stack; use 0.0.0.0 for IPv4-only
    port: 7893
    firewall: false
    udp: true
    udp-timeout: 60      # per-flow idle timeout, seconds; 0 is an error
```

`max-connections` bounds live UDP flows for this listener too (`0` =
unlimited). Per-flow queues are additionally bounded in datagram count and
bytes, so a burst cannot pin unbounded memory; replies are written through a
bounded transparent-socket cache (one FD per distinct original destination).

IPv6 support is a **capability requirement**, not a `uname` guess: the kernel
needs `AF_INET6`, the IPv6 transparent/original-destination sockopts, an
IPv6-capable netfilter TPROXY backend, and IPv6 policy routing. Upstream
nftables TPROXY starts at Linux 4.18; this guide does not claim a first
release for the IPv6 cmsg sockopts or for OEM backports — verify the target
kernel or device. If you do not deploy IPv6, omit the `ip6` table and the
`ip -6` policy-routing lines below.

Deployer-side steering for UDP (`tcp` stays on `redirect` in the output chain
as in the steps below unless you separately configure `transparent: true`):

```bash
# fwmark → local delivery, the policy-routing half of TPROXY: one per family
ip rule add fwmark 0x1 lookup 100
ip route add local 0.0.0.0/0 dev lo table 100
ip -6 rule add fwmark 0x1 lookup 100
ip -6 route add local ::/0 dev lo table 100

nft -f - <<'NFT'
table ip meow_udp {
  # Same bypass set as `meow_gateway` below — keep them in sync.
  set reserved4 {
    type ipv4_addr; flags interval;
    elements = { 0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
                 172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4 }
  }
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth0" fib daddr type local return        # gateway's own services (incl. DNS to LAN_IP)
    iifname "eth0" udp dport 53 return                # let the nat-chain DNS hijack handle DNS
    iifname "eth0" ip daddr @reserved4 return         # never proxy LAN/VPN-internal ranges
    iifname "eth0" meta l4proto udp tproxy ip to 127.0.0.1:7893 meta mark set 0x1 accept
  }
}
table ip6 meow_udp6 {
  set reserved6 {
    type ipv6_addr; flags interval;
    elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
  }
  chain pre {
    type filter hook prerouting priority mangle; policy accept;
    iifname "eth0" fib daddr type local return
    iifname "eth0" udp dport 53 return
    # Only when dns.fake-ip-range6 is this ULA pool: capture it BEFORE the
    # broad fc00::/7 bypass. Substitute your pool; remove this rule otherwise.
    iifname "eth0" ip6 daddr fdfe:dcba:9876::/64 meta l4proto udp tproxy ip6 to [::1]:7893 meta mark set 0x1 accept
    iifname "eth0" ip6 daddr @reserved6 return
    iifname "eth0" meta l4proto udp tproxy ip6 to [::1]:7893 meta mark set 0x1 accept
  }
}
NFT
```

The `tproxy … to` address and port must select a bound same-family socket.
The example pairs `127.0.0.1:7893`/`[::1]:7893` with a wildcard listener. A
specific-address listener must use that same address in the rule (for example
`[fd77::1]:7893`), and `::1` is valid only when your rules intentionally steer
to the loopback-bound socket.

**The exemptions matter — a bare `meta l4proto udp` catch-all breaks your own
gateway.** `prerouting` also sees packets destined to the gateway itself:
without `fib daddr type local return`, a LAN client's DNS to `LAN_IP:53` gets
TPROXY'd with `orig_dst = LAN_IP:53` and routed by meow to a destination where
nothing listens. Ordering bites too: this chain runs at `priority mangle`
(-150), *before* the `nat`/`dstnat` (-100) `meow_gateway` chain, so once a
datagram is TPROXY'd the DNS DNAT hijack never sees it — `udp dport 53 return`
keeps forwarded DNS on the hijack path. Only the v4 hijack is enabled by
default; v6 DNS is hijacked only when the optional v6 DNAT rule below is
enabled and meow DNS listens on IPv6. Otherwise clients must use the gateway's
DNS address to receive fake-ip/fake-AAAA answers. The reserved bypasses mirror the
TCP chain's `meow_gateway` behaviour. Keep the fake-ip ranges out of broad
bypasses: when `fake-ip-range6` is inside ULA, its explicit capture rule must
precede `fc00::/7` as shown, or clients receive fake AAAA answers that never
reach meow.

**Scope the rules to your LAN interface** (`iifname "eth0"` above — substitute
yours). Keep host-originated packets out of the TPROXY path: do not add a
matching `output` rule for UDP. If the fwmark you pick collides with meow's
`routing-mark`, meow's own outbound gets steered into the local table — keep
the two mark values distinct.

For the systemd unit below, persist these same `ip meow_udp` and `ip6
meow_udp6` table definitions as `/etc/meow/udp.nft` (without the shell heredoc
wrapper). The one-shot service then loads them together with `gateway.nft`.

Replies are sent with the **original destination** as source address and port
(via a per-family transparent socket bound per destination on first use), so
clients see responses as if they came from the real server. Capability and
failure-mode notes:

- `IP_TRANSPARENT`/`IPV6_TRANSPARENT` need `CAP_NET_ADMIN`/`CAP_NET_RAW` — a
  listener-socket failure surfaces as a startup error, never a silent TCP-only
  degrade.
- There is no fallback when the original-destination control message is
  missing, truncated, in the wrong family, or malformed: the datagram drops.
  `IPV6_PKTINFO` has no destination port, `getsockname` is only the listener
  address, and REDIRECT's `SO_ORIGINAL_DST` is not the UDP TPROXY interface.
- Reply sockets bind the original destination verbatim; for destinations
  below port 1024 that bind additionally needs `CAP_NET_BIND_SERVICE`, which
  `CAP_NET_ADMIN` does not imply. Reply sockets also do **not** carry
  `routing-mark`/SO_MARK — mark-based policy rules must not steer reply
  packets (whose source is the forged destination) toward the local table.
- Reply binds deliberately have no `SO_REUSEADDR`. `EADDRINUSE` means a real
  local service already owns that original destination endpoint (or it
  collides with the same-family listener endpoint); such replies drop and the
  bind is retried with backoff. Passing the self-target guard does not
  guarantee the reply bind succeeds.
- A wildcard listener drops a flow whose recovered `orig_dst` aims at the
  listener's port on one of the host's own addresses (the self-reinjection
  guard, checked against a `getifaddrs` snapshot taken when the listener
  starts) — remote services that merely share the port number pass through.
  If the interface table cannot be enumerated the listener falls back to the
  conservative rule (any same-port destination is self) and warns once.
- The sniffer is TCP-only: UDP flows carry no recovered SNI, so under
  redir-host they route by IP. Point LAN clients at fake-ip (or the snoop
  table) if UDP domains matter.

---

## Prerequisites

- A Linux host with `nftables` (`nft`) installed and meow running as **root**
  (or with `CAP_NET_ADMIN` — needed to manage nftables).
- IP forwarding enabled:
  ```bash
  sysctl -w net.ipv4.ip_forward=1
  sysctl -w net.ipv6.conf.all.forwarding=1   # only if you proxy IPv6
  ```
- Throughout, substitute your values:
  - `LAN_IFACE` — the interface facing the LAN (e.g. `eth0`)
  - `LAN_IP` — the host's address on that interface (e.g. `192.168.1.1`)
  - tproxy port `7893`, DNS port `1053`, `routing-mark` `9527` (any unused values)

---

## Step 1 — meow config

```yaml
mixed-port: 7890            # optional: keep a normal HTTP/SOCKS port for testing
allow-lan: true
bind-address: '::'
mode: rule
ipv6: true
external-controller: '[::]:9090'

# DIRECT sockets carry this mark so the output-chain rule skips them (loop avoid).
routing-mark: 9527

# Explicit tproxy listener on a non-loopback address (see note above).
listeners:
  - name: tproxy-gw
    type: tproxy
    listen: '::'
    port: 7893

# Recover the hostname for direct-IP TLS/HTTP where no DNS lookup happened.
# Keep override-destination false so domain-based routing is not clobbered.
sniffer:
  enable: true
  override-destination: false
  sniff:
    TLS:  { ports: [443] }
    HTTP: { ports: [80] }

dns:
  enable: true
  listen: 0.0.0.0:1053       # LAN :53 is DNAT'd here by the gateway nft rules
  enhanced-mode: fake-ip     # or redir-host — see next section
  fake-ip-range: 198.18.0.0/16
  # fake-ip-range6: fdfe:dcba:9876::/64  # optional fake AAAA pool (needs ipv6: true)
  nameserver:
    - 223.5.5.5              # use resolvers appropriate to your region
    - 1.1.1.1

proxies:    [ ... ]
proxy-groups: [ ... ]
rules:      [ ... ]
```

Validate without starting anything:

```bash
meow -f /etc/meow/config.yaml -t
```

---

## DNS mode: fake-ip vs redir-host

A transparent gateway recovers only the destination **IP** from the kernel. To
route by domain (and to let the upstream proxy resolve names), meow needs to map
that IP back to a hostname. The `enhanced-mode` you pick decides how:

| | **fake-ip** | **redir-host** |
|---|---|---|
| DNS answer | synthetic IP from `fake-ip-range` (instant) | real IP resolved upstream |
| IP→domain recovery | exact, 1:1 from the fake-IP pool | DNS-snoop reverse table (last writer wins) |
| `GEOIP` / `IP-CIDR` rules | **inert** — the dst is always a fake IP | **work** — the dst is the real IP |
| First-hit latency (new domain) | none | one upstream DNS round-trip |
| AAAA / IPv6 | v4-only pool returns NODATA for AAAA → clients use v4/TCP; `fake-ip-range6` + `ipv6: true` can synthesize fake AAAA | not suppressed; handle v6 yourself |
| DNS-poisoning exposure | none (no local resolve) | resolves locally; mitigate with domain rules → proxy |
| Unmatched-domain fallback | fake IP never matches IP rules → hits your final `MATCH` rule | real IP is classified by `GEOIP`/`IP-CIDR` |

**Choose fake-ip if** routing is driven mainly by domain rules and a final
`MATCH,<proxy>` catch-all. It is fail-safe (unmatched → proxy), fast, and
immune to DNS poisoning — the common choice for censorship-circumvention
gateways.

> **fake-ip pitfall:** any rule that matches the fake range — e.g.
> `IP-CIDR,198.18.0.0/16,DIRECT` (common in Clash rule sets as a no-op for
> normal mode) — will catch **every** domain that has no explicit `DOMAIN` rule
> (its dst is now a fake IP) and send it `DIRECT` to an unroutable address.
> Remove or repoint such a rule, and make sure your last rule is
> `MATCH,<a proxy group>`.

With `fake-ip-range6`, a live fake AAAA reverse-maps to its hostname before
routing; the outbound may resolve to either family, while client-facing replies
keep the fake IPv6 address and original destination port as their source. A
datagram to a pool address with no live mapping drops before a flow is created.
If the v6 pool is inside ULA (`fc00::/7`), both the TCP redirect table and any
UDP TPROXY table must capture that pool **before** the broad ULA bypass — see
the ordering comments in the rules below.

**Choose redir-host if** your rule set leans on IP classification —
`GEOIP,CN`, large `IP-CIDR` tiers for split routing — because those only work
on real IPs. Trade-offs: a one-time DNS round-trip per new domain, no automatic
AAAA suppression, and a tail risk that an unmatched **foreign** domain poisoned
to a local-region IP routes DIRECT and fails (comprehensive domain rules
mitigate this). Domain rules still work via the snoop reverse table + sniffer.

Both modes intercept identically; only the DNS/routing behaviour differs. You
can switch with a one-line `enhanced-mode` change and a restart.

---

## Step 2 — gateway nftables rules

> **Shortcut:** [`scripts/tproxy-gateway-linux.sh`](../scripts/tproxy-gateway-linux.sh)
> generates and loads exactly the table below and enables forwarding —
> `sudo scripts/tproxy-gateway-linux.sh up` (autodetects interface/IP; `down` to
> remove, `status` to inspect). The helper is **TCP-only**: it does not install
> UDP TPROXY tables or the fwmark/policy-routing half — use the manual `udp:
> true` recipe above for that. macOS has an experimental pf equivalent,
> [`scripts/tproxy-gateway-macos.sh`](../scripts/tproxy-gateway-macos.sh). The
> manual rules below are the reference the scripts implement.

meow creates the `output`-chain table for its own traffic (unless the
listener runs `firewall: false` — then the host's own traffic is also
yours to cover). Add this table for **forwarded** LAN traffic. Save as
`/etc/meow/gateway.nft`:

```nft
#!/usr/sbin/nft -f
# Intercept traffic FORWARDED from LAN clients and hand it to meow's tproxy
# listener. meow's own `inet meow_tproxy_*` table only covers the host's own
# (output-chain) traffic.

table inet meow_gateway {
    # Destinations that must NOT be proxied. The fake-ip range is deliberately
    # absent — those MUST be redirected so meow can map fake IP -> domain.
    set reserved4 {
        type ipv4_addr; flags interval
        elements = {
            0.0.0.0/8, 10.0.0.0/8, 127.0.0.0/8, 169.254.0.0/16,
            172.16.0.0/12, 192.168.0.0/16, 224.0.0.0/4, 240.0.0.0/4
        }
    }
    set reserved6 {
        type ipv6_addr; flags interval
        elements = { ::1/128, fc00::/7, fe80::/10, ff00::/8 }
    }

    chain prerouting {
        type nat hook prerouting priority dstnat; policy accept;

        # Only forwarded LAN traffic; leave host-local traffic to meow's table.
        iifname != "eth0" return

        # 1. DNS hijack: send LAN DNS to meow's resolver. The v4 rule is
        # required for the fake-ip path. The v6 rule is optional and requires
        # dns.listen to bind an IPv6 address reachable from LAN clients;
        # substitute the gateway's LAN v6 address. Without it, clients using
        # a hard-coded off-LAN v6 resolver bypass meow DNS and get no fake AAAA.
        meta nfproto ipv4 meta l4proto { tcp, udp } th dport 53 \
            dnat ip to 192.168.1.1:1053
        # meta nfproto ipv6 meta l4proto { tcp, udp } th dport 53 \
        #     dnat ip6 to [fd77::1]:1053

        # 2. Traffic addressed to the gateway itself (SSH, API, ...) -> leave.
        fib daddr type local return

        # 3. LAN / reserved / non-routable destinations -> leave (not proxied).
        #    If dns.fake-ip-range6 is inside fc00::/7, it MUST be captured
        #    before the broad ULA bypass. Uncomment and substitute your pool:
        # ip6 daddr fdfe:dcba:9876::/64 meta l4proto tcp redirect to :7893
        ip  daddr @reserved4 return
        ip6 daddr @reserved6 return

        # 4. Everything else (incl. fake-ip range) -> meow's tproxy port.
        meta l4proto tcp redirect to :7893
    }
}
```

Replace `eth0`, `192.168.1.1`, the optional `[fd77::1]`, `:1053`, and `:7893` with your values. Notes:

- The DNS hijack catches clients that point at any resolver (e.g. `8.8.8.8`),
  forcing them through meow so fake-ip / snooping works. Clients that talk to a
  resolver on the **same subnet** reach it directly (L2) and bypass this — point
  such clients' DNS at the gateway, or at an off-subnet address.
- If you do **not** proxy IPv6, drop the `redirect` for v6 by adding
  `meta nfproto ipv6 return` before rule 4. With the default v4-only fake-ip
  pool, AAAA receives NODATA and clients use v4 anyway; enabling
  `fake-ip-range6` is an explicit choice to carry fake AAAA traffic.
- Bypassing all of RFC1918/ULA means LAN↔LAN traffic is never proxied. Keep
  the fake-ip ranges (`198.18.0.0/16` and, when configured, your
  `fake-ip-range6`) **out** of the bypass sets — or capture them before a
  broader containing bypass as shown for ULA.

Load it (and tear down with `nft delete table inet meow_gateway`).

---

## Step 3 — systemd wiring

Run meow as a normal service, and load the gateway rules in a companion unit
tied to meow's lifecycle so they load/unload together.

`/etc/systemd/system/meow.service` (standard) runs
`meow -f /etc/meow/config.yaml` as root.

`/etc/systemd/system/meow-gateway.service`:

```ini
[Unit]
Description=meow transparent-gateway nftables rules (forwarded LAN -> tproxy)
After=meow.service
Wants=meow.service
PartOf=meow.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStartPre=/sbin/sysctl -w net.ipv4.ip_forward=1
ExecStartPre=/sbin/sysctl -w net.ipv6.conf.all.forwarding=1
ExecStartPre=/etc/meow/wait-tproxy.sh
ExecStart=/usr/sbin/nft -f /etc/meow/gateway.nft
ExecStop=/usr/sbin/nft delete table inet meow_gateway
ExecStop=-/usr/sbin/nft delete table ip meow_udp
ExecStop=-/usr/sbin/nft delete table ip6 meow_udp6

[Install]
WantedBy=multi-user.target
```

The `wait-tproxy.sh` `ExecStartPre` closes a boot-time race: `meow-gateway`
otherwise loads the prerouting `REDIRECT` a second or two **before** meow has
bound the listener, so freshly-forwarded connections briefly hit a closed port.
The script blocks until the port is listening (then proceeds regardless, so the
redirect still loads fail-closed if meow is slow). Save as
`/etc/meow/wait-tproxy.sh` (`chmod +x`):

```sh
#!/bin/sh
# Block until meow has bound the tproxy listener (:7893) before the gateway
# redirect rules load. Cap at 30s, then proceed anyway (fail-closed).
for i in $(seq 1 150); do
    ss -lnt | grep -q ":7893" && exit 0
    sleep 0.2
done
echo "meow-gateway: :7893 not listening after 30s; loading rules anyway"
exit 0
```

```bash
systemctl daemon-reload
systemctl enable --now meow meow-gateway
```

`PartOf=meow.service` makes the gateway rules reload whenever meow restarts, so
the two never drift.

For a `udp: true` listener the same unit must also persist the policy-routing
half — `nft -f` does not cover `ip rule`/`ip route … table 100`, so UDP would
silently die on reboot without them:

```ini
ExecStart=/usr/sbin/nft -f /etc/meow/udp.nft
ExecStart=/sbin/ip rule add fwmark 0x1 lookup 100
ExecStart=/sbin/ip route add local 0.0.0.0/0 dev lo table 100
ExecStart=/sbin/ip -6 rule add fwmark 0x1 lookup 100
ExecStart=/sbin/ip -6 route add local ::/0 dev lo table 100
ExecStop=/sbin/ip rule del fwmark 0x1 lookup 100
ExecStop=/sbin/ip route del local 0.0.0.0/0 dev lo table 100
ExecStop=/sbin/ip -6 rule del fwmark 0x1 lookup 100
ExecStop=/sbin/ip -6 route del local ::/0 dev lo table 100
```

Omit the two `ip -6` start/stop pairs on an IPv4-only UDP deployment.

---

## Step 4 — point clients at the gateway

On each LAN client (or via your DHCP server): set the **default gateway** to
`LAN_IP`, and set **DNS** to `LAN_IP` (or any off-subnet resolver, which the
DNS-hijack rule will redirect). With DHCP serving the gateway as both router and
DNS, clients need no manual setup.

---

## Verification

On the gateway:

```bash
# Listener is up on a NON-loopback address (::/0.0.0.0, not 127.0.0.1):
ss -lntp | grep 7893
# Both tables present (with managed firewall — no `meow_tproxy*` table
# exists under `firewall: false`, where your own table plays its role):
nft list tables | grep meow_tproxy  # meow-managed, output chain (per-instance name)
nft list table inet meow_gateway    # this guide, prerouting chain

# With `udp: true`, readiness is per family. `[::]` should show one UDP
# socket on each of 0.0.0.0 and ::; a specific-family listen shows only its
# own. The policy routes and deployer tables must exist for the same family:
ss -lunp | grep ':7893'
ip rule show | grep 'fwmark 0x1 lookup 100'
ip -6 rule show | grep 'fwmark 0x1 lookup 100'
ip route show table 100 | grep '^local'
ip -6 route show table 100 | grep '^local'
nft list table ip meow_udp
nft list table ip6 meow_udp6
```

A UDP rule target must also point at a bound same-family socket (the recipe's
`127.0.0.1:7893` and `[::1]:7893` both select the wildcard pair). Add a
`counter` statement to your own rules when you need hit evidence.

From a LAN client that uses the gateway:

```bash
# fake-ip mode: expect an address from your fake-ip-range (e.g. 198.18.x.x)
dig +short example.com
# A blocked/foreign site should load through the proxy:
curl -sS -o /dev/null -w '%{http_code}\n' https://www.google.com
```

On the gateway, meow logs each connection with the recovered host and matched
rule — confirm the client's source IP appears:

```
[::ffff:192.168.1.50]:54321 --> www.google.com:443 match DOMAIN-SUFFIX(google.com) using Proxies[HK-01]
```

(`::ffff:` prefix is the v4-mapped form when the listener binds `::`. The
brackets name the node the `Proxies` group dials through.)

---

## Android and boxed deployment notes

The validated surface here is a Linux-target meow binary plus the netfilter
contract above. It is not evidence for a native `target_os = "android"`/bionic
build, and this repository has not device-tested BoxProxy/box_for_root's exact
`ndc` commands, rule ordering, or netfilter backend. Treat those as separate
validation, not as a drop-in consequence of the Linux listener supporting
IPv6.

Before claiming such a replacement, record on the physical device: the binary
target and kernel; whether root/SELinux permits the IPv6 transparent and
original-destination sockopts; the actual `iptables`/`ip6tables` or nftables
backend; and both families' rules, policy tables, and hit evidence. Check that
marks and rule priorities do not collide with netd. Capturing host-originated
application traffic must first re-inject it into the `prerouting` path — do not
apply the TPROXY target directly in `output` — and must exclude meow's own
outbound and transparent replies rather than globally rewriting netd state.

Be careful with UDP `socket transparent` divert shortcuts. meow's reply
sockets bind the original destination only to send replies; a socket-divert
rule can select those sockets and locally swallow later packets, bypassing the
explicit ingress socket. Whether a given BoxProxy release uses such a rule is
unverified here, and first-packet success is not evidence either way. Only
claim Android-device compatibility after continuous UDP requests in both
families pass on the device's real rules without later-packet misdelivery or a
mark loop.

---

## Limitations & troubleshooting

- **UDP needs `udp: true`.** Without it, UDP/443 from the LAN is not
  proxied; the default v4-only fake-ip pool's AAAA NODATA nudges clients onto
  TCP, and you can additionally `REJECT` UDP/443 in `prerouting` to force the
  fallback. With `udp: true` the scope notes above apply (Linux,
  `prerouting` only, with per-family IPv4/IPv6 rules).
- **Connections refused / time out from clients, fine on the host.** The
  listener is bound to `127.0.0.1` — declare it via `listeners:` with a
  non-loopback `listen` (see [Step 1](#step-1--meow-config)).
- **One site hangs while others work (fake-ip).** A rule is matching the
  fake-ip range and sending it `DIRECT` — see the fake-ip pitfall above.
- **Unmatched foreign domains fail (redir-host).** Local resolution returned a
  poisoned/region IP that an IP rule sent `DIRECT`; add a domain rule or
  consider fake-ip.
- **UDP sockets are listening but no UDP flow is logged.** Re-check the
  family-specific chain, not just the socket: the `tproxy` target must select a
  bound same-family socket, the packet must carry the fwmark into that family's
  `local … dev lo` table, and the chain must be mangle/`prerouting` TPROXY.
  meow drops datagrams whose original-destination control message is missing,
  truncated, in the wrong family, or malformed; there is deliberately no
  fallback. A successful TCP redirect does not prove this UDP control-message
  path.
- **A UDP flow is logged but the client receives no reply.** Look for
  `cannot bind transparent reply socket` warnings. Usual causes are a real
  local service already owning the original endpoint, a destination port below
  1024 without `CAP_NET_BIND_SERVICE`, or deployer rules that re-capture the
  reply path. Reply sockets have no `SO_REUSEADDR` and no `routing-mark` by
  design.
- **The gateway proxies its own traffic too.** meow's `output`-chain table
  redirects the host's own outbound TCP (proxy-server IPs and `routing-mark`
  DIRECT sockets are bypassed automatically). This is inherent to enabling a
  tproxy listener.
- **macOS:** the built-in firewall uses a `pf` anchor with UID-based loop
  avoidance and supports local interception only; this gateway recipe is
  Linux/nftables-specific. Destinations listening on ephemeral-range ports
  (`net.inet.ip.portrange.first`–65535, default 49152+) are not intercepted:
  the `rdr` exempts them so the listener's own replies — which target the
  client's ephemeral port and re-traverse `lo0` — aren't redirected back into
  the listener (issue #354). Setup guide: [tproxy-macos.md](tproxy-macos.md).
