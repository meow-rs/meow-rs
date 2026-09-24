# Transparent proxy on macOS (pf) — experimental

Proxy **this host's own outbound TCP traffic** on macOS without touching
application proxy settings, using a `tproxy` listener and pf. For forwarding
*other* devices' traffic see [tproxy-gateway.md](tproxy-gateway.md) (the macOS
gateway script is experimental); for the strategic, more capable path on macOS
(UDP, IPv6, IP-literal capture without pf) see [tun.md](tun.md).

**Status: experimental, scope settled (#248).** Requires a build containing
the `DIOCNATLOOK` direction fix (#353) and the lo0 reply-exemption fix (#355)
— `main` since July 2026, first release after 0.18.0. Scope: **IPv4 TCP
only**, no UDP, and the *managed* ruleset intercepts **loopback-traversing
traffic only**. Steering real outbound (`en0`) traffic is deliberately left
to the manual `route-to` detour below rather than having meow rewrite the
host's pf configuration — automated physical-interface steering was
considered under #248 and rejected in favor of the TUN inbound
([tun.md](tun.md)), which captures all traffic without pf, handles UDP, and
is the recommended path for a fully transparent macOS setup.

## How it works

Configuring `tproxy-port` makes meow (which must run as root — pf requires it)
auto-load a pf anchor `com.apple/com.meow.tproxy.<pid>.<seq>` on startup and
flush it on exit. The anchor is unique per listener instance, and startup also
flushes leftover `com.meow.tproxy*` anchors whose owning pid is dead or was
recycled by a non-meow process (plus the
legacy shared `com.apple/com.meow.tproxy`) — a crashed instance's `rdr` would
otherwise keep redirecting traffic to a dead port (issue #621):

```
no rdr on lo0 proto tcp from any to any port 49152:65535   # let replies through (#354)
rdr pass on lo0 proto tcp from any to any -> 127.0.0.1 port <tproxy-port>
pass out quick on lo0 proto tcp from any to any user 0     # meow's own dials skip
pass out quick on lo0 proto tcp from any to 127.0.0.0/8
```

Every TCP connection that traverses `lo0` is redirected into the listener,
which recovers the pre-translation destination from pf's state table
(`DIOCNATLOOK`) and routes it through your rules like any other connection.
Loop avoidance is UID-based: connections made *by root* bypass interception,
so meow (running as root) can dial out freely — run client apps as a normal
user.

The `no rdr` line exempts destination ports in the kernel's ephemeral range
(`sysctl net.inet.ip.portrange.first`, default 49152+): on `lo0` every packet
passes pf twice, and without the exemption the listener's own replies would be
re-redirected into itself, wedging every handshake. Consequence: destinations
listening on ephemeral-range ports are not intercepted (they connect directly).

## Quick start

```yaml
# config.yaml
mode: rule
tproxy-port: 7893     # binds 127.0.0.1; meow manages the pf anchor
proxies:
  - { name: my-proxy, type: ss, server: ..., port: ..., cipher: ..., password: ... }
rules:
  - MATCH,my-proxy
```

```bash
sudo ./meow -f config.yaml
# → INFO pf anchor 'com.apple/com.meow.tproxy.<pid>.0' loaded
# → INFO TProxy listener 'tproxy' started on 127.0.0.1:7893
```

Out of the box this intercepts only traffic that already traverses `lo0`
(connections to loopback-aliased addresses). That is enough for the
[verification rig](../scripts/README.md) but not for real browsing — read on.

`scripts/tproxy-local-macos.sh up|down|status` wraps the above and confirms
the anchor came up.

## External firewall management (`firewall: false`)

A named `listeners:` entry can skip the managed anchor entirely (issue #563):

```yaml
listeners:
  - name: tproxy
    type: tproxy
    listen: 127.0.0.1:7893
    firewall: false   # meow never invokes pfctl for this listener
```

With `firewall: false` meow installs no anchor and removes none on exit — you
own the whole ruleset and its lifecycle. A working pf ruleset needs ALL of
these; skipping any one wedges or loops intercepted traffic:

- **`no rdr` ephemeral exemption first.** Translation rules are first-match:
  `no rdr on lo0 proto tcp from any to any port <ephemeral_first>:65535`
  must precede your `rdr` — otherwise the listener's own replies re-match
  the `rdr` on their second `lo0` traversal and every intercepted handshake
  wedges (issue #354).
- **`rdr` to the listener's bind address.** `DIOCNATLOOK` is queried with
  the listener's *bound* address as the lookup key, so `listen:
  127.0.0.1:7893` pairs with `rdr … -> 127.0.0.1 port 7893`. A `listen:
  0.0.0.0` listener whose `rdr` targets `127.0.0.1` accepts connections and
  then silently fails orig-dst recovery — keep the two addresses equal.
- **UID bypass** (`pass out quick on lo0 … user <meow-uid>`) so meow's own
  outbound connections are not re-intercepted.
- **Loopback bypass** (`pass out quick on lo0 proto tcp from any to
  127.0.0.0/8`) — otherwise the host's own loopback TCP gets redirected into
  the listener.
- **An evaluated anchor/ruleset.** A `pfctl -a` anchor only runs if the
  active ruleset references it — the stock `/etc/pf.conf` evaluates only
  `com.apple/*` children (meow's managed anchor is
  `com.apple/com.meow.tproxy.<pid>.<seq>` — still a direct `com.apple/`
  child — for exactly this reason), so either nest your anchor under
  `com.apple/` or wire an `rdr-anchor`/`load anchor` reference yourself.
  pf must also be enabled (`pfctl -e`) for the `DIOCNATLOOK` lookup to find
  NAT state.

The listener still accepts redirected TCP and recovers the original
destination via the pf state-table lookup (`DIOCNATLOOK` on `/dev/pf`), so
your rules must use `rdr` — a plain `pass` + connect leaves no NAT state to
look up. See
[tproxy-gateway.md](tproxy-gateway.md#firewall-false--fully-external-rule-management)
for the Linux/nft side of the same contract.

## Intercepting real outbound traffic (`route-to lo0`)

The host's outbound connections to remote IPs leave via `en0` and never touch
`lo0`, so meow's managed `rdr` cannot see them (issue #248 §2). To intercept
them, add a pf rule that detours matching outbound packets through `lo0`.
meow does **not** install this for you. Verified recipe (child anchors under
`com.apple/*` are evaluated by the stock `/etc/pf.conf`):

```bash
# Example: proxy all TCP to 1.1.1.1. Widen the "to" spec to taste.
echo '
pass out quick on en0 proto tcp from any to 1.1.1.1 user root
pass out quick on en0 route-to lo0 inet proto tcp from any to 1.1.1.1
' | sudo pfctl -a com.apple/com.meow.routeto -f -
```

Rule 1 is mandatory: it lets meow's *own* (root) outbound dials to the same
destinations escape the detour — without it every proxied connection loops
straight back into the listener. Rule 2 steers everyone else's packets into
`lo0`, where the managed `rdr` picks them up.

Notes:

- **Scope the `to` spec deliberately.** Start with specific IPs/tables and
  widen once you trust your rules; a `to any` detour combined with a broken
  ruleset can take the host's entire TCP egress down with it.
- If meow runs as a dedicated non-root… it can't — pf needs root. The `user
  root` escape therefore always matches meow. If you run *other* root
  processes whose traffic you wanted proxied, they are bypassed too (same
  trade-off as the managed anchor's UID loop avoidance).
- The anchor does not survive reboot; re-load it at startup (LaunchDaemon) or
  keep it in `/etc/pf.conf` via an `anchor`/`load anchor` pair.
- Remove with `sudo pfctl -a com.apple/com.meow.routeto -F all`.

End-to-end check (this exact recipe is verified on macOS 26 VMs): with the
anchor loaded, `curl http://1.1.1.1/` from a non-root shell returns normally
and meow logs

```
INFO meow_listener::tproxy: 192.168.x.x:49219 --> 1.1.1.1:80 match MATCH() using DIRECT
```

## Limitations

| Limitation | Detail |
|------------|--------|
| IPv4 TCP only | `DIOCNATLOOK` recovery is IPv4; UDP is not intercepted (use [TUN](tun.md)) |
| Ephemeral-port destinations bypass | dst ports ≥ `net.inet.ip.portrange.first` (default 49152) connect directly (#354) |
| Manual `route-to` for real traffic | meow only manages the `lo0` rdr (#248 §2) |
| Root-owned traffic bypasses | UID loop avoidance skips everything root sends |
| Not reboot-persistent | both meow's anchor (by design) and your `route-to` anchor |

## Troubleshooting

```bash
# The anchor is per-instance: com.apple/com.meow.tproxy.<pid>.<seq> —
# find it under com.apple first, then inspect it.
sudo pfctl -a com.apple -sAnchors | grep com.meow.tproxy
sudo pfctl -a com.apple/com.meow.tproxy.<pid>.<seq> -sn   # rdr + no-rdr present?
sudo pfctl -a com.apple/com.meow.tproxy.<pid>.<seq> -sr   # uid/loopback bypasses present?
sudo pfctl -ss | grep <tproxy-port>                       # states being created?
```

A state stuck in `SYN_SENT:ESTABLISHED` alongside a second, reversed state
means replies are being re-redirected — you are running a build without the
#355 exemption. No states at all means the traffic never traversed `lo0`
(missing `route-to`). meow accepting but logging nothing at `info` usually
means original-destination recovery failed; re-run with `log-level: debug`
(errors on the accept path are logged at debug).

The scripted rig `scripts/verify-tproxy-setup.sh` / `verify-tproxy-test.sh`
asserts the whole loopback path (listener, anchor, interception, recovery) on
a disposable loopback alias — **it rewrites pf state; run it in a VM, not on
a workstation you care about.**
