# TUN inbound — transparent proxy on Windows (and everywhere else)

Last updated: 2026-08-17. Tracks the `listener-tun` feature (issue
[#326](https://github.com/madeye/meow-rs/issues/326)).
Audience: users who want system-wide transparent proxying on a platform
without a tproxy/REDIRECT firewall — Windows first and foremost. The same
inbound works on Linux and macOS.

The TUN inbound creates an L3 network device (`wintun` on Windows, `tun` on
Linux, `utun` on macOS), terminates the raw IP packets in a userspace TCP/IP
stack ([lwIP](https://github.com/madeye/lwip), via the in-tree tun2socks
bindings), and dispatches the
resulting TCP/UDP flows through meow's normal routing engine — rules, proxy
groups, statistics, and the REST API all behave exactly as they do for the
other inbounds.

## Quick start

```yaml
# config.yaml
mode: rule

dns:
  enable: true
  enhanced-mode: fake-ip          # REQUIRED for the v1 TUN flow (see below)
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true
  auto-route: true                # routes the fake-ip range into the device
  dns-hijack:
    - any:53                      # answer DNS entering the tun in-process

proxies:
  # ... your outbounds ...
rules:
  # ... your rules ...
```

Then:

1. **Windows**: official release zips already contain [`wintun.dll`](https://www.wintun.net/)
   next to `meow.exe`. From-source builds embed the official signed DLL in
   `meow.exe` and extract it on first TUN start if no sidecar is found
   (override the compile-time file with `MEOW_WINTUN_DLL=`). You can still
   fetch a sidecar with `scripts/fetch-wintun.sh --target x86_64-pc-windows-msvc --outdir .`.
   Run the shell elevated ("Run as administrator"). **Linux/macOS**: run as root
   or grant `CAP_NET_ADMIN`.
2. Point the OS resolver at an address **inside the fake-ip range**, e.g.
   `198.18.0.2`. On Windows:

   ```
   netsh interface ip set dns name="meow" static 198.18.0.2
   ```

   (The adapter is named after `tun.device`, default platform-chosen.) On
   Linux/macOS set the DNS server for your active connection the same way.
3. Start meow. DNS queries route into the tun (the range is on-link/routed),
   `dns-hijack` answers them with fake IPs, connections to those fake IPs
   route into the tun, and rules match on the recovered domain.

## How v1 stays loop-free (and what it doesn't capture)

The classic TUN failure mode is the routing loop: with a global default
route into the device, meow's *own* outbound dials (proxy upstreams and
DIRECT traffic alike) re-enter the tun and recurse. mihomo solves this with
platform-specific socket tricks (SO_MARK, interface binding). meow v1
side-steps the entire problem class:

- **Only the fake-ip range is routed into the device** (`auto-route` installs
  exactly that route; the device's own subnet is on-link anyway if you assign
  it inside the range).
- Outbound dials always target **real** IPs, which are never inside the fake
  range — so they take the physical route and cannot loop. No marks, no
  interface binding, no bypass routes.

The trade-off: **traffic that never does a DNS lookup (IP-literal
connections) is not captured.** For domain-based traffic — the overwhelming
majority — capture is complete. Global capture ("route everything") is the
opt-in `auto-route: global` mode below (#375).

Consequences:

- `dns.enhanced-mode: fake-ip` is effectively required. With `redir-host`,
  `auto-route` has nothing safe to route and warns; you can still add routes
  to the device manually, but you are then responsible for loop avoidance.
- UDP flows (including QUIC) to fake IPs are captured and routed per-rule.
  The flow table is bounded at 1024 live entries — at capacity the
  least-recently-active flow is evicted — and `dns-hijack` runs at most 64
  concurrent in-process answers (queries it cannot decide locally past
  that bound are dropped; clients retry). Live occupancy is observable via
  `Tunnel::tun_udp_flow_count`.
- A destination **inside** the fake-ip range with **no live allocation** —
  stale across a restart, evicted by pool wrap, or a literal connect into
  the range — is dropped rather than dialed: dialing it would route
  straight back into the device (issue #618). The drop applies on every
  inbound, not just TUN.
- ICMP echo requests entering the device are answered by the userspace
  stack itself — `ping` to a fake IP confirms the tun is up, but is not an
  end-to-end probe of the remote host.

## Global route mode — `auto-route: global` (experimental, Linux-only)

Tracked on [#375](https://github.com/madeye/meow-rs/issues/375). Routes
**all IPv4 traffic** into the device instead of just the fake-ip range, so
IP-literal connections are captured too:

```yaml
tun:
  enable: true
  auto-route: global
  # outbound-interface: eth0   # optional; auto-detected from the default route
  dns-hijack:
    - any:53
```

How each loop-avoidance piece works:

1. **Split default routes.** `auto-route: global` installs `0.0.0.0/1` and
   `128.0.0.0/1` into the device. The two /1s are more specific than the
   physical `0.0.0.0/0`, so the original default route is never touched and
   teardown is a plain route delete — no restore step that can be lost to a
   crash.
2. **Outbound interface binding.** Every outbound socket meow creates (proxy
   upstream dials, DIRECT, marked sockets) is bound to the physical
   interface with `SO_BINDTODEVICE` *before* connect/bind, so its packets
   take the physical route regardless of the routing table. The interface is
   `tun.outbound-interface` if set, otherwise auto-detected from
   `/proc/net/route` **before** the split defaults go in. If the binding
   cannot be installed, startup **fails closed** — no default routes are
   installed without loop avoidance.
3. **Own-resolver hostname dials.** Proxy-server domains are resolved
   through meow's resolver hook (installed at startup), not libc's
   `getaddrinfo`, so those lookups don't depend on the OS resolver's
   routing either.

Scope and caveats:

- **Linux-only for now.** macOS (`IP_BOUND_IF`) and Windows
  (`IP_UNICAST_IF`) bindings are follow-ups on #375; `auto-route: global`
  on those platforms is a startup error. On Windows the fake-ip mode
  remains the supported transparent path.
- IPv4 only, matching the rest of the TUN v1 flow (no `inet6-address`).
- `fake-ip` DNS mode is still recommended so domain rules match; global
  mode adds IP-literal capture on top rather than replacing the DNS flow.
- Requires root/`CAP_NET_ADMIN` like the rest of the TUN inbound.

Verification on a Linux host (or VM):

```bash
sudo ./meow -f config.yaml            # global mode active
curl 1.1.1.1                          # IP literal — captured (check meow logs)
ip route get 1.1.1.1                  # shows the tun device
curl https://example.com              # domain flow — still captured
# teardown: stop meow, then confirm both /1 routes are gone:
ip route | grep -c '/1 dev' # → 0
```

## `tun:` reference

| Field | Default | Notes |
|-------|---------|-------|
| `enable` | `false` | Master switch. Requires a build with the `listener-tun` feature (included in `full`). |
| `device` | platform-chosen | Adapter name. macOS always auto-assigns `utunN`. |
| `mtu` | `1500` | Hard error below 1280 (userspace-stack minimum). |
| `inet4-address` | `172.19.0.1/30` | CIDR assigned to the device. |
| `auto-route` | `true` | What to route into the device at startup (removed on shutdown): `true`/`fake-ip` = the fake-ip range; `global` = all IPv4 (experimental, Linux-only, see above); `false` = nothing. |
| `outbound-interface` | auto-detect | Physical interface outbound sockets bind to in `global` mode. Ignored otherwise. |
| `dns-hijack` | off | List of targets; any `:53` entry turns on in-process answering of UDP :53 flows entering the device. Non-`:53` entries warn and are ignored. |
| `udp-timeout` | `60` | Seconds of idle before a UDP flow is evicted. |
| `max-connections` | `256` | Inherited from the top-level `max-connections` (`0` = unlimited); bounds **TCP** flows — a change while TUN runs restarts the listener. The UDP flow table has its own fixed bound (1024 live flows, least-recently-active eviction) that `max-connections` does not adjust. |

mihomo fields meow does not implement (`stack`, `strict-route`,
`auto-detect-interface`, `inet6-address`, `endpoint-independent-nat`,
UID filters, …) are accepted with a startup warning and ignored — same
forward-compat policy as the rest of the config surface.

Runtime reloads: `PUT /configs` reconciles the listener against the
committed `tun:` section — an `enable` transition starts/stops it, and
any other semantic parameter change (or changed fake-IP inputs)
restarts it so the running stack matches the stored config (#543).
No-op respellings and the warn-only fields above do not bounce the
device; a failed (re)start — including the initial startup's — rolls
committed `tun.enable` back to `false`, so a re-PUT of the same file
(with `enable: true`) is an off→on transition and retries the spawn.
The PUT still returns 204 — the failure is logged, not surfaced. The
one case where an unchanged re-PUT does *not* retry is a listener that
dies *after* a successful start (no rollback ran, committed stays
`true`); revival there needs an `enable` flip or a parameter change.

## Relationship to the tproxy inbound

| | tproxy (`tproxy-port`) | tun (`tun:`) |
|---|---|---|
| Platforms | Linux (nftables), macOS (pf, experimental) | Windows, Linux, macOS |
| Mechanism | firewall REDIRECT + `SO_ORIGINAL_DST` | L3 device + userspace stack |
| TCP | ✓ | ✓ |
| UDP | ✗ | ✓ |
| Privileges | root (firewall rules) | root / CAP_NET_ADMIN / elevation |
| Capture scope | host's own output traffic | everything routed into the device |

On Linux, tproxy remains the lighter-weight choice for host-only TCP
proxying; tun adds UDP and works without firewall integration. On Windows,
tun is the only transparent option. For LAN-gateway setups, see
[tproxy-gateway.md](tproxy-gateway.md).
