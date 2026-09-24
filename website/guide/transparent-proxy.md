# Transparent Proxy

A transparent proxy intercepts traffic at the kernel and routes it through
meow-rs **without** any per-app proxy settings. The backend is platform-specific:

| Platform | Mechanism | Config |
| --- | --- | --- |
| **Windows** | [Wintun](https://www.wintun.net/) TUN adapter + userspace stack | `tun:` |
| Linux | nftables `REDIRECT` (tproxy) or TUN | `tproxy-port` or `tun:` |
| macOS | pf redirect (experimental) or utun | `tproxy-port` or `tun:` |

On Windows there is no nftables/pf equivalent, so **Wintun is the transparent-proxy
path**. Official Windows release zips ship `wintun.dll` next to `meow.exe`.

## Windows (Wintun)

```yaml
mode: rule

dns:
  enable: true
  enhanced-mode: fake-ip          # required for v1 TUN capture
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true
  auto-route: true                # routes the fake-ip range into the adapter
  dns-hijack:
    - any:53
```

1. Use a build with the `listener-tun` feature (included in `full`, so release
   binaries have it). Official zips ship `wintun.dll` next to `meow.exe`. If
   the sidecar is missing, meow extracts the official signed DLL embedded in
   the binary (next to the exe, or under `%LOCALAPPDATA%\meow\`). From-source
   Windows builds fetch that DLL at compile time.
2. Run the process **elevated** ("Run as administrator", or the Windows service).
3. Start meow. `auto-route` + `dns-hijack` point the OS resolver at a loopback
   DNS server that returns fake IPs; connections to those IPs enter the Wintun
   adapter and go through the normal rule engine.

v1 captures **domain-based** traffic only (the fake-IP range). Outbound dials
always go to real IPs, so they cannot loop back into the adapter. IP-literal
connections are not captured. Full field reference and the loop-freedom
argument are in
[docs/tun.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tun.md).

## Linux / macOS tproxy

meow-rs implements host tproxy with a `REDIRECT` strategy plus firewall rules
it installs and tears down automatically.

```yaml
tproxy-port: 7893
routing-mark: 9527     # Linux: SO_MARK for loop avoidance
```

## How tproxy works

- **REDIRECT-based; TCP only under the managed firewall.** Traffic is redirected to
  the TProxy listener, and the original destination is recovered via
  `SO_ORIGINAL_DST` (Linux) or a pf state-table lookup (`DIOCNATLOOK`, macOS).
  With `firewall: false` + `udp: true`, Linux/IPv4 UDP TPROXY is an opt-in
  (see below); otherwise UDP is not intercepted.
- **Loop avoidance.** meow-rs's own outbound (the `DIRECT` adapter) is marked so the
  firewall skips it — on Linux via `SO_MARK` (`routing-mark`), on macOS via a UID bypass.
- **Proxy-server bypass.** The IPs of your configured upstream proxy servers are
  bypassed automatically, so the tunnel's own traffic isn't re-captured.
- **RAII firewall.** Rules are installed when the listener starts and removed on shutdown.

### Linux (nftables)

meow-rs creates a per-listener-instance `inet meow_tproxy_<pid>_<seq>`
table hooking the **output** chain:

- bypass the `routing-mark` mark,
- bypass loopback (`127.0.0.0/8`, `::1`),
- bypass each upstream proxy IP,
- redirect remaining TCP to the TProxy port.

Tables are unique per listener instance, so teardown removes only what
that instance created; on startup meow sweeps `meow_tproxy*` tables whose
owning pid is dead or now belongs to a non-meow process (pid reuse), plus
the legacy shared `meow_tproxy` name — an uncleaned redirect would
otherwise keep black-holing traffic after a crash.

### macOS (pf)

A per-instance `com.apple/com.meow.tproxy.<pid>.<seq>` anchor with `rdr`
redirect on `lo0`, a UID bypass for meow's own traffic, loopback and
proxy-IP bypasses. Stale anchors owned by dead pids (and the legacy shared
`com.apple/com.meow.tproxy` anchor) are flushed at startup. (macOS pf
support is experimental.)

## External firewall management

A named `listeners:` entry can opt out of the managed firewall with
`firewall: false` (issue #563):

```yaml
listeners:
  - name: gateway
    type: tproxy
    listen: "0.0.0.0"
    port: 7893
    firewall: false
```

meow then **never** invokes nftables or pfctl for this listener: no rules are
installed, probed, or removed, and the upstream proxy-IP bypass list is not
collected. The data plane is unchanged — the listener still accepts TCP
`REDIRECT` connections and recovers the original destination.

The deployer's responsibilities, all of them:

- install the `REDIRECT` rules that steer traffic into the listener, on whatever
  backend you prefer (iptables, nftables, pf, an external firewall manager);
- provide the loop-prevention bypass (a `routing-mark`/UID exemption for meow's
  own outbound and upstream server IPs), or meow's outbound will be re-captured;
- own startup/shutdown ordering — rules installed before meow binds refuse or
  fail-open depending on your design; meow cleans up nothing;
- pick a **fixed** port. `port: 0` resolves after external rules would already
  need to exist, so it only works if you discover the bound port via
  `GET /listeners` and install rules afterwards.

On macOS the `DIOCNATLOOK` lookup is keyed on the listener's **bound** address:
`listen: 0.0.0.0` pairs badly with `rdr` rules targeting `127.0.0.1` (the lookup
misses and connections drop after accept). Keep the `rdr` target equal to the
`listen` address — see [tproxy-macos.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tproxy-macos.md)
for the full pf contract.

Out of scope: `firewall: false` does **not** add an iptables backend or change
the TCP path (the listener remains TCP `REDIRECT`), and takes effect at
startup only — a config change needs a restart. The shorthand `tproxy-port`
always keeps the managed firewall.

### UDP TPROXY (`udp: true`, Linux/IPv4 only)

`firewall: false` is also the prerequisite for the opt-in UDP path (issue
#564): a named listener with `udp: true` additionally binds a transparent UDP
socket on the same port, recovers each datagram's original destination from
`IP_ORIGDSTADDR`, routes it through the normal rules, and sends replies with
the original destination as source address and port.

Constraints: Linux + IPv4 only (`listen` must be a v4 address, not `'::'`);
the deployer owns the `prerouting` TPROXY rules and fwmark→local-table policy
routing (meow installs nothing for UDP); the recipe covers `prerouting`
only — host-originated UDP needs an `output`-chain TPROXY setup of your
own; `udp-timeout` (default
60s) evicts idle flows and `max-connections` bounds flow count. Reply sockets
bind the original destination verbatim — ports below 1024 additionally need
`CAP_NET_BIND_SERVICE`, and reply sockets carry no `routing-mark`. See
[docs/tproxy-gateway.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tproxy-gateway.md)
for the full external rule recipe.

## Host-only vs. LAN gateway

The built-in firewall hooks the **output** chain, so it only captures the **host's own**
outbound traffic. It is **not** a forwarding gateway on its own.

To proxy *other devices'* traffic you must:

1. Declare the TProxy listener with a **non-loopback** `listen` (the shorthand
   `tproxy-port` hard-binds `127.0.0.1` and won't work as a gateway):

   ```yaml
   listeners:
     - name: gateway
       type: tproxy
       port: 7893
       listen: "0.0.0.0"
   ```

2. Add **prerouting** firewall rules to redirect forwarded LAN traffic (not auto-managed).
3. Hijack DNS (DNAT port 53 to meow's resolver), and pick a DNS mode — FakeIP vs
   redir-host — depending on your topology.

::: tip Helper scripts & full recipe
The repo ships `scripts/tproxy-gateway-linux.sh` (nftables) and
`scripts/tproxy-gateway-macos.sh` (pf, experimental) to automate the gateway plumbing.
The complete walkthrough — prerouting rules, DNS-mode trade-offs, and systemd wiring —
is in
[docs/tproxy-gateway.md](https://github.com/meow-rs/meow-rs/blob/main/docs/tproxy-gateway.md).
:::

## Recovering domains

Because TProxy hands meow-rs an IP destination, domain rules need a way to learn the
hostname. Two mechanisms cover this:

- The [sniffer](./sniffer) extracts SNI / `Host` from the connection itself.
- [DNS](./dns) `redir-host` or `fake-ip` mode keeps an IP→domain reverse table.

Combine a TProxy listener with the sniffer and a DNS mode for full domain-based routing of
intercepted traffic.

## DSCP routing

On the TProxy path you can route by the IP DSCP field:

```yaml
rules:
  - DSCP,46,Proxy      # e.g. EF / voice traffic
```

`DSCP` only ever matches on the TProxy listener.
