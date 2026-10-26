# TUN inbound — transparent proxy on Windows (and everywhere else)

Last updated: 2026-10-26. Tracks the `listener-tun` feature (issue
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
  enhanced-mode: fake-ip          # recommended: domain rules match TUN traffic
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query

tun:
  enable: true                    # captures all traffic, DNS included

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
2. Start meow. With `auto-route` and `dns-hijack` left at their defaults,
   everything the host sends goes through the device (global route scope,
   below) — IPv4, and IPv6 too once the device has an `inet6-address` —
   and DNS is answered in-process: in fake-ip mode meow points the OS
   resolver at an address inside the fake-ip range (`198.18.0.2`; the
   loopback DNS server on Windows) and restores it on stop, and a UDP :53
   query to any other server that enters the device is answered too.
   Connections to the fake IPs route into the device, and rules match on
   the recovered domain.

`auto-route: fake-ip` narrows the capture to the fake-ip range,
`dns-hijack: []` turns the in-process DNS off — see *Route scopes*.

## Windows: address setup, adapter reuse, and conflicts

On Windows the adapter's addresses do not go through the OS's
duplicate-address detection: meow turns that check off on its own adapter
and creates each configured address ready to use, so traffic and DNS work
the moment the TUN listener reports ready. Without it a fresh address
stays *tentative* while the OS checks it for duplicates, and a tentative
address cannot send packets. Three consequences of how that is done:

- **A reused adapter is reconfigured.** An adapter left behind by an
  unclean shutdown carries its previous run's addresses; meow logs a
  warning, opens it — or recreates it, when the driver has orphaned the
  leftover — and assigns exactly the configured addresses, replacing
  every non-link-local one it finds, IPv6 included. Stale IPv6 addresses
  are removed even when no `inet6-address` is configured: the adapter
  ends up with exactly what the config says. An adapter that outlives
  meow also keeps duplicate-address detection off.
- **A conflicted address fails loudly, then rotates.** An address another
  adapter still holds fails the attempt instead of starting the device
  half-configured; each retry gets a new adapter name, and from the third
  attempt the address of both families also rotates — IPv4 steps a few
  addresses up from the configured one, IPv6 cycles through the addresses
  of its subnet.
- **A failed attempt rolls the adapter back.** The failed attempt removes
  an address it managed to add and restores the ones it replaced — the
  adapter is left as it was found — and the listener moves on to the
  next one.

## Route scopes

The classic TUN failure mode is the routing loop: with a default route
into the device, meow's *own* outbound dials (proxy upstreams and DIRECT
traffic alike) re-enter the tun and recurse. `auto-route` picks one of
two scopes, which rule the loop out differently:

- **`true` (the default) — global scope.** Everything the host sends is
  routed into the device, IP literals included; meow's own sockets are
  bound to the physical interface so they cannot loop (*Global route
  scope* below). Linux, macOS and Windows; on other targets `true` means
  fake-ip scope. `global` is an explicit spelling of the same.
- **`fake-ip` — the fake-ip range only.** Loop-free by construction:
  outbound dials always target **real** IPs, which are never inside the
  fake range, so they take the physical route. No interface binding, no
  routes beyond the one range. The trade-off: **traffic that never does a
  DNS lookup (IP-literal connections) is not captured**, and
  `dns.enhanced-mode: fake-ip` is required — with `redir-host` there is no
  range to route, so `auto-route` warns and installs nothing; you can
  still add routes to the device manually, but you are then responsible
  for loop avoidance.
- **`false`** — no routes; add your own.

Flow handling is the same in both scopes:

- UDP flows (including QUIC) are captured and routed per-rule.
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
- TCP flows are dialed as soon as the client sends its first bytes, or
  after a 200 ms sniff window if it stays silent (mihomo's pre-dial peek).
  Server-first protocols — SMTP, POP3, IMAP, FTP, MySQL, VNC, SSH — wait
  for the server's banner without sending anything, so they see it after
  that window plus the dial (before #695 they were reset after 15 s).
  Through a Shadowsocks outbound add one more 200 ms: the outbound waits
  that long for client bytes to send with its request header before
  sending the header alone. A connection that closes or resets inside
  the window (connect scans, aborted reconnects) is dropped before it is
  matched, counted or dialed.
- ICMP echo requests entering the device are answered by the userspace
  stack itself — `ping` to a fake IP confirms the tun is up, but is not an
  end-to-end probe of the remote host.

## Global route scope — the default

Tracked on [#375](https://github.com/madeye/meow-rs/issues/375). Routes
**all IPv4 traffic** the host sends into the device, not just the fake-ip
range, so IP-literal connections are captured too — and all IPv6 traffic
as well when the device is given an `inet6-address`:

```yaml
tun:
  enable: true
  # auto-route: true                       # the default; `global` is the same
  # outbound-interface: eth0               # optional; auto-detected from the default route
  # inet6-address: fdfe:dcba:9876::1/126   # optional; also capture IPv6
```

Status per platform — "implemented" means the code path exists, compiles
and is unit-tested; all three have been exercised with real routes (the
scope of each run is in the table):

| Platform | Outbound binding | Interface auto-detection | Status |
|----------|------------------|--------------------------|--------|
| Linux | `SO_BINDTODEVICE` (by name) | `/proc/net/route` | **Verified** for IPv4 and IPv6 with real routes and policy rules in containers (Linux 6.8 aarch64, Linux 7.0 x86_64) — see *What was verified on Linux* below. Not yet run on a bare host. |
| macOS | `IP_BOUND_IF` / `IPV6_BOUND_IF` (by index) | routing table, unscoped `0.0.0.0/0` | Experimental. IPv4 and IPv6 exercised in a macOS 26.6 VM (arm64, single interface, DIRECT outbound) — see *Verified on macOS* below; not yet on a multi-interface host or through a proxy outbound. |
| Windows | `IP_UNICAST_IF` / `IPV6_UNICAST_IF` (by index) | routing table, lowest route + interface metric | Experimental. IPv4 and IPv6 exercised on Windows 11 arm64 with a Wintun adapter and one physical NIC (DIRECT outbound): auto-detected and explicit alias, TCP + UDP, runtime reload, teardown. Choosing between several default routes by metric is unit-tested only. |

IPv6 capture (`inet6-address`) is **experimental**. It has been exercised
in the same three setups: the device gets the address, the IPv6 routes
are installed and removed, and IPv6 TCP and UDP flows are captured and
relayed. A public IPv6 destination was reached on macOS and Windows; the
Linux lab had no IPv6 uplink.

How each loop-avoidance piece works:

1. **Routes into the device.** On Linux the device's default routes go in
   a routing table of meow's own (`1835364215`, "meow" in ASCII), and
   policy rules send the host's own traffic there while leaving the
   replies on connections it accepted, and traffic it forwards, on the
   main table:

   | pref | IPv4 | IPv6 |
   |------|------|------|
   | 9200 | `not dport 53 lookup main suppress_prefixlength 0` | same |
   | 9201 | `iif lo from <device subnet> lookup 1835364215` | same |
   | 9202 | `iif lo from 0.0.0.0 lookup 1835364215` | `iif lo from ::/1 goto 9205` |
   | 9203 | | `iif lo from 8000::/1 goto 9205` |
   | 9204 | | `iif lo lookup 1835364215` |
   | 9205 | | `nop` |

   - 9200: a main-table route more specific than the default — the LAN, a
     Docker bridge, a static route, the fake-ip range — keeps winning,
     except for DNS: a query to a LAN resolver still reaches `dns-hijack`.
   - A socket that has not chosen a source address yet (`connect` /
     `sendto` on an unbound socket, the common case) goes to the device
     and takes the device's address as its source; the flow's later
     packets match 9201.
   - A flow that already has another source — the reply on a connection
     accepted on the physical interface, a socket bound to a physical
     address — falls through to the main table. IPv6 rules cannot match
     "no source", so IPv6 skips every flow that has one (9202, 9203) and
     sends the rest to the device.
   - `iif lo` limits all of this to the host's own traffic: forwarded
     traffic (containers, VMs, a gateway's LAN clients) keeps the main
     table, where meow routes the fake-ip range into the device, so their
     domain flows are still captured.

   The rules need a kernel with policy routing (`CONFIG_IP_MULTIPLE_TABLES`)
   and the `dport` selector (Linux 4.17); without them meow warns and falls
   back to the split routes below.

   **macOS and Windows install split default routes**: `0.0.0.0/1` and
   `128.0.0.0/1` into the device. The two /1s are more specific than the
   physical `0.0.0.0/0`, so the original default route is never touched and
   teardown is a plain route delete — no restore step that can be lost to a
   crash. With `inet6-address` set, `::/1` and `8000::/1` are installed the
   same way. On every platform, without `inet6-address` no IPv6 route is
   installed and IPv6 traffic keeps bypassing the device.

   **macOS installs a different set**, because a route whose destination
   is the all-zero address breaks the outbound binding there: a socket
   scoped with `IP_BOUND_IF` to the primary interface has no scoped route
   of its own, so the kernel falls back to looking the default route up
   by key (`0.0.0.0` / `::`) — and finds `0.0.0.0/1` on the `utun`
   instead of the real default. The interface does not match the
   socket's, and every dial meow makes fails with `Network is
   unreachable` (IPv6: `No route to host`), for destinations in both
   halves. So on macOS the lower half is covered without that key:
   `1.0.0.0/8`, `2.0.0.0/7`, `4.0.0.0/6`, `8.0.0.0/5`, `16.0.0.0/4`,
   `32.0.0.0/3`, `64.0.0.0/2`, plus `128.0.0.0/1` — and for IPv6
   `100::/8`, `200::/7`, `400::/6`, `800::/5`, `1000::/4`, `2000::/3`,
   `4000::/2`, plus `8000::/1`. The skipped `0.0.0.0/8` is never a
   destination; the skipped `::/8` contains the IPv4-mapped and NAT64
   (`64:ff9b::/96`) ranges, which are therefore not captured on macOS.
2. **Outbound interface binding.** Every outbound socket meow creates (proxy
   upstream dials including Hysteria2's QUIC socket, DIRECT, DNS upstreams,
   marked sockets) is bound to the physical interface *before*
   connect/bind, so its packets take the physical route regardless of the
   routing table: `SO_BINDTODEVICE` on Linux, `IP_BOUND_IF` /
   `IPV6_BOUND_IF` on macOS, `IP_UNICAST_IF` / `IPV6_UNICAST_IF` on
   Windows. The interface is `tun.outbound-interface` if set (on Windows:
   the interface *alias*, e.g. `Ethernet` or `Wi-Fi`), otherwise
   auto-detected from the real IPv4 `0.0.0.0/0` route — the TUN's own `/1`
   split routes are skipped, so detection is safe while a previous
   listener's routes are still up. On macOS the default of a non-primary
   interface (`netstat -rn` flag `I`) is skipped; on Windows the default
   with the lowest route + interface metric wins. The binding is installed
   as soon as the config is parsed, ahead of the first startup dial
   (provider and geodata fetches, health checks), so no long-lived session
   opened during startup escapes it (#695); the TUN listener then owns it
   and gives it up with its routes. Runtime reloads do the same — see
   *Runtime reloads* below. If the binding cannot be installed, startup
   **fails closed** — no default routes are installed without loop
   avoidance.
3. **Own-resolver hostname dials.** Proxy-server domains are resolved
   through meow's resolver hook (installed at startup), not libc's
   `getaddrinfo`, so those lookups don't depend on the OS resolver's
   routing either.

Scope and caveats:

- **Linux, macOS and Windows.** Elsewhere `auto-route: true` means
  fake-ip scope, and an explicit `auto-route: global` fails at startup
  rather than install default routes it cannot protect.
- **macOS and Windows bind by interface index**, resolved once when the
  binding is installed. If the physical interface is destroyed and
  re-created (not a plain link flap), the index changes and outbound dials
  fail until the TUN listener restarts (`PUT /configs` with a changed
  `tun:` section, or a restart of meow). Linux binds by name and follows
  the re-created interface.
- **Loopback upstreams on macOS and Windows are left unbound.** A socket
  scoped to a physical interface cannot connect to `127.0.0.1` on macOS,
  and loopback traffic never follows the TUN's routes, so TCP dials to a
  loopback address (a local upstream proxy, a SIP003 plugin) skip the
  binding there, as do UDP sockets bound to a loopback address. Linux
  binds every socket.
- **IPv6 is opt-in.** Without `inet6-address` the device is IPv4-only and
  IPv6 traffic is not captured (it leaves through the physical interface
  untouched). With it, outbound IPv6 sockets are bound to the same
  physical interface as IPv4 ones — the interface is still chosen from
  the *IPv4* default route. If that interface has no IPv6 connectivity,
  DIRECT dials to IPv6 destinations fail (clients fall back to IPv4);
  proxied ones are unaffected. `inet6-address` is ignored, with a warning,
  in fake-ip scope: it has no IPv6 range to route.
- `fake-ip` DNS mode is still recommended so domain rules match; global
  scope adds IP-literal capture on top rather than replacing the DNS flow.
- Requires root/`CAP_NET_ADMIN` (Administrator on Windows) like the rest
  of the TUN inbound.
- **Only traffic that follows the default route is captured.** Anything
  more specific wins: destinations on a directly connected subnet (the
  LAN, a Docker bridge) and any static route you added keep using their
  own interface and never reach meow — on Linux except DNS (rule 9200).
- **Traffic the host forwards** (containers, VMs, LAN clients of a
  gateway) is captured only when it goes to a fake IP. On Linux it is
  never sent to meow's table; making a host a gateway for other devices
  is covered in [tproxy-gateway.md](tproxy-gateway.md).
- **Inbound connections from other networks.** On Linux the replies on
  connections the host accepted keep the physical route (policy rules
  above): an SSH session from another subnet, a server on the host, and
  meow's own `allow-lan` listeners and `external-controller` keep working.
  Before the policy rules — and still on a Linux kernel that falls back to
  split routes — such a reply was routed into the device and never
  reached the peer. On macOS and Windows the split routes are in the main
  table, and whether a reply follows them into the device has not been
  verified; source-address-based route selection on both should keep it
  on the physical interface. Peers on the directly connected subnet are
  unaffected everywhere (more-specific route). Please report results on
  #375 before relying on remote access to a macOS or Windows machine with
  TUN on.
- **`ping` proves nothing.** The userspace stack answers ICMP echo itself
  for *every* address routed into the device, so `ping 203.0.113.77`
  "succeeds" for a host that does not exist. Probe with TCP or UDP.
- **Teardown.** A normal stop (SIGINT/SIGTERM, or a reload that disables
  TUN) removes the policy rules (or the `/1` routes), the device and the
  routes through it, and restores `/etc/resolv.conf`. After a `kill -9` on
  Linux the kernel destroys the device and with it the device address and
  every route through it, so IP connectivity is back at once; the policy
  rules stay but point at an empty table, which lookups fall through, and
  the next start replaces them. The `dns-hijack` resolver redirect
  survives too: `/etc/resolv.conf` still names an address in the fake-ip
  range, so name resolution fails until meow starts again (it recovers
  the original from `/etc/resolv.conf.meow-backup`) or you restore that
  file by hand.

Verification on a Linux host (or VM). Pick targets *off* the local subnet
(see above), and make sure `curl` is not itself configured to use a proxy
(`http_proxy` / `https_proxy` in the environment bypass the TUN):

```bash
sudo ./meow -f config.yaml            # global scope active; the log shows
                                      #   outbound sockets bound to 'eth0'
ip rule | grep '^92'                  # the policy rules (9200-9202)
ip route show table 1835364215        # default dev meow-tun
ip route get 1.1.1.1                  # dev meow-tun table 1835364215
curl 1.1.1.1                          # IP literal — captured (check meow logs)
curl https://example.com              # domain flow — still captured
dig @9.9.9.9 example.com              # UDP: answered by dns-hijack with a fake IP
# no loop: meow's own dials leave by the physical interface, never the tun
sudo tcpdump -ni eth0 'tcp[tcpflags] & tcp-syn != 0'       # the outbound SYNs
sudo tcpdump -ni meow-tun src host <eth0 address>          # stays empty
# inbound: from another network, ssh / curl to the host still connects
# with tun.inet6-address set:
ip -6 addr show dev meow-tun          # the configured address
ip -6 rule | grep '^92'               # 9200-9205
curl 'http://[2606:4700:4700::1111]/' # IPv6 literal — captured (the reply needs
                                      #   IPv6 connectivity on the physical interface)
# teardown: stop meow, then confirm the rules are gone:
{ ip rule; ip -6 rule; } | grep -c '^92'   # → 0
```

### What was verified on Linux

Run for #375 in privileged containers (Docker on a Linux 6.8 aarch64 VM,
`aarch64-unknown-linux-musl` build with default features): a client
container whose default route points at a router container, and a server
container behind that router, so the test targets are reached through the
default route rather than an on-link one. Not run on a bare host, and not
with systemd-resolved or NetworkManager managing the resolver. That run
predates the policy rules: it used the split `/1` routes, which the
fallback still installs.

The policy rules were run in the same topology (Docker on Linux 7.0
x86_64, `CAP_NET_ADMIN` only, debug build), with a `tun:` section of just
`enable: true` and `inet6-address`:

- the rules, the table's default routes and the fake-ip route in the main
  table go in; IPv4 and IPv6 literals to the server are captured, and
  `curl` to a domain through the system resolver (redirected by meow) is
  captured with its domain;
- connections from the router's far-side address (another subnet) and
  from the LAN reach a server on the host, IPv4 and IPv6;
- DNS to an on-link LAN resolver and to a remote one is answered with
  fake IPs, with no `dns-hijack` key in the config;
- a second container using the host as its gateway reaches a fake IP
  through meow, and an IP literal past it, untouched;
- `PATCH /configs` restarts (`mtu`, `auto-route: fake-ip` and back) leave
  exactly one set of rules; SIGTERM removes them all; after `kill -9` the
  host's direct connectivity works with the rules left behind, and the
  next start replaces them.

- **Startup**: the interface is auto-detected (`eth0`), the binding is
  logged before the first dial, `0.0.0.0/1` + `128.0.0.0/1` go into the
  device; with `inet6-address` the device carries the address and
  `::/1` + `8000::/1` are added.
- **Capture**: IP-literal TCP and UDP, IPv4 and IPv6, to the server
  container and (IPv4) to a public address; domains through `dns-hijack`
  and fake-ip; the same through a SOCKS5 outbound (TCP and UDP ASSOCIATE)
  whose server is a hostname. 64 MiB transfers arrive bit-identical in
  both families.
- **No loop**: every outbound SYN / datagram shows on `eth0` with the
  physical source address and none on the device, across 200 concurrent
  connections and 100 UDP flows; CPU is idle afterwards and the
  connection table drains.
- **Teardown**: SIGTERM removes all four `/1` routes, the device and the
  resolver redirect, and direct connectivity is back; `kill -9` leaves
  only the resolver redirect (see *Teardown* above).
- **Reloads** (`PUT /configs`): off → global, global → off, global →
  global (`mtu` change, adding/removing `inet6-address`) and a reload
  into a bogus `outbound-interface` (TUN ends up off, no routes) all leave
  routes, device and resolver consistent; 30 consecutive global → global
  restarts keep the device name.
- **Fail-closed**: a non-existent `outbound-interface`, or no IPv4 default
  route to auto-detect from, starts meow without the TUN listener and
  without any `/1` route.

The same checks on macOS:

```bash
sudo ./meow -f config.yaml
route -n get 1.1.1.1 | grep interface   # → the utun device
curl 1.1.1.1                            # captured (check meow logs)
netstat -rn -f inet | grep -c utun      # after stopping meow: 0
```

### Verified on macOS

Run on macOS 26.6 (arm64 VM, one interface `en0`, `MATCH,DIRECT`), each
checked against meow's log and `tcpdump` on both `en0` and the `utun`:

- Startup auto-detects `en0`, logs the `IP_BOUND_IF` binding and installs
  the eight IPv4 routes above on the `utun`; an explicit
  `outbound-interface: en0` behaves the same, and a non-existent
  interface fails closed — the device is removed, no route is installed
  and the rest of meow keeps running with TUN off.
- IP-literal TCP (`curl http://1.1.1.1`) and fake-ip domain flows are
  captured and relayed. meow's own dial leaves `en0` from the interface
  address; nothing sourced from that address re-enters the `utun`, and
  CPU and the connection count stay flat over an idle minute.
- UDP round-trips through the device (`dig @223.5.5.5` with `dns-hijack`
  off, NTP).
- Loopback is unaffected: the REST API, a `127.0.0.1` listener, and a
  dial meow itself makes to `127.0.0.1` through the mixed port.
- With `inet6-address`: the address is assigned, the eight IPv6 routes
  are installed, and IPv6-literal TCP and UDP flows are captured and
  leave `en0` from its IPv6 address.
- A global → global reload (`PUT /configs` changing `mtu`) comes back
  with routes and binding intact.
- SIGTERM removes every route, the device and the DNS override. After
  `kill -9` the kernel destroys the `utun` and its routes with the
  process, so connectivity returns on its own — but with `dns-hijack`
  the system DNS servers stay pointed at the fake-ip range and name
  resolution is broken until meow is started and stopped cleanly once
  (or `networksetup -setdnsservers <service> empty`).

Not covered by that run: proxy outbounds (only DIRECT was dialed), a
host with several active interfaces, and an interface whose index
changes under a running listener.

### Verified on Windows

Run on Windows 11 arm64 (VM, Wintun adapter, one physical NIC `Ethernet`,
`MATCH,DIRECT`):

- Startup auto-detects the physical adapter, logs the `IP_UNICAST_IF`
  binding and puts `0.0.0.0/1` + `128.0.0.0/1` on the Wintun adapter; an
  explicit `outbound-interface: Ethernet` (the interface *alias*) behaves
  the same, and an unknown alias fails closed — no routes, no adapter,
  meow keeps running without TUN.
- IP-literal TCP and UDP to a LAN and a public address, and a domain
  through `dns-hijack` / fake-ip, are captured and relayed; meow's own
  dial leaves from the physical address while the captured client socket
  sits on the TUN address, and CPU and the connection count stay flat.
- The REST API on `127.0.0.1` keeps answering with the routes up.
- With `inet6-address` the adapter gets the address, `::/1` + `8000::/1`
  are installed, and IPv6 TCP and UDP to public addresses are relayed.
- A `PUT /configs` out of and back into global scope removes and
  restores routes, adapter and DNS.
- A hard kill (`taskkill /F`) cannot leak the routes — they disappear
  with the Wintun adapter — but with `dns-hijack` it leaves the physical
  adapter's DNS servers pointing at `127.0.0.1` / `::1`, so name
  resolution fails until meow runs again: the next start detects the
  leftover and resets the adapter to DHCP DNS when it stops cleanly.

Not covered by that run: proxy outbounds (only DIRECT was dialed) and
choosing between several default routes by metric (one NIC).

Still to be run by the maintainers on Windows — please report results
on #375:

```powershell
# Windows (elevated)
.\meow.exe -f config.yaml
Find-NetRoute -RemoteIPAddress 1.1.1.1 | Select-Object InterfaceAlias  # → the tun adapter
curl.exe 1.1.1.1                       # captured (check meow logs)
Get-NetRoute -DestinationPrefix 0.0.0.0/1, 128.0.0.0/1   # after stopping meow: none
```

## `tun:` reference

| Field | Default | Notes |
|-------|---------|-------|
| `enable` | `false` | Master switch. Requires a build with the `listener-tun` feature (included in `full`). |
| `device` | platform-chosen | Adapter name. macOS always auto-assigns `utunN`. On Windows a same-named leftover adapter is reopened — or recreated, when the driver has orphaned it — and reconfigured either way (see *Windows: address setup, adapter reuse, and conflicts*). |
| `mtu` | `1500` | Hard error below 1280 (userspace-stack minimum). |
| `inet4-address` | first /30 of `dns.fake-ip-range` (`198.18.0.1/30`) | CIDR assigned to the device. Like mihomo, the default takes an address the fake-IP pool never hands out, outside LAN and Docker networks. A fixed private subnet can collide with one: a device on a Docker network's gateway address cuts the host off from that network's containers. |
| `inet6-address` | none | IPv6 CIDR assigned to the device, e.g. `fdfe:dcba:9876::1/126` — a string, or mihomo's list form (only the first entry is used). Only honoured in global scope, where it also captures IPv6 (experimental, see above); ignored with a warning otherwise. An invalid CIDR is a hard error. |
| `auto-route` | `true` | What to route into the device at startup (removed on shutdown): `true` = everything the host sends, IPv6 too with `inet6-address` (global scope; Linux, macOS and Windows, fake-ip scope elsewhere); `global` = the same; `fake-ip` = the fake-ip range only; `false` = nothing. See *Route scopes*. |
| `outbound-interface` | auto-detect | Physical interface outbound sockets bind to in global scope — the interface name on Linux/macOS (`eth0`, `en0`), the interface alias on Windows (`Ethernet`). Ignored otherwise. |
| `dns-hijack` | on | In-process answering of UDP :53 flows entering the device, and in fake-ip mode the OS resolver redirect. Absent = on; a list with any `:53` entry = on; `[]` = off. Non-`:53` entries warn and are ignored. |
| `udp-timeout` | `60` | Seconds of idle before a UDP flow is evicted. |
| `max-connections` | `256` | Inherited from the top-level `max-connections` (`0` = unlimited); bounds **TCP** flows (a flow takes its slot when it leaves the 200 ms sniff window, so one that closes inside it never occupies one) — a change while TUN runs restarts the listener. The UDP flow table has its own fixed bound (1024 live flows, least-recently-active eviction) that `max-connections` does not adjust. |

mihomo fields meow does not implement (`stack`, `strict-route`,
`auto-detect-interface`, `mtu-v6`, `endpoint-independent-nat`,
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

`PATCH /configs` with a `tun` object, which is what a mihomo GUI's TUN
switch sends, runs the same reconcile. The keys it carries are merged
over the committed section: an omitted key, `enable` included, keeps its
value, the fields of the table above apply and any other key is ignored.
A section that fails to parse is rejected with 400 and nothing applied;
a failed (re)start rolls `enable` back as above, but the PATCH answers
500 with the reason instead of 204.

In global route scope a reload binds outbound sockets before its first dial,
exactly like startup (#695). A `PUT /configs` whose candidate selects
global scope installs the candidate's binding right after taking
the config-mutation lane — before the ECH pre-resolve, the config build's
provider fetches and the health checks the swap restarts — and hands it to
the (re)spawned listener. (The proxy / group / subscription commits that
share the lane pre-install too, but they never change `tun:`, so with
global scope running the binding is already in effect for them.) The
binding is owned, not set: owners stack, and the newest live one is in
effect, so

- a **rejected** PUT (or a failed spawn) gives its binding up and the
  running listener's is back in effect — or none, if TUN was off;
- a **global → global restart** (e.g. an `mtu` change) never leaves a gap:
  the new binding is in effect before the old listener is stopped, and the
  old listener's teardown cannot clear it;
- an `outbound-interface` change (or off → global) takes effect for every
  socket the reload opens, and once the new listener is up the reload
  flushes the sessions opened *before* it, which are not bound to the new
  interface and would loop into the device: tracked TCP connections
  (unless the reload's routing swap already closed them), UDP sessions —
  the tunnel's NAT table and every listener's UDP flows (SOCKS5, TUN,
  TProxy, Shadowsocks inbound) — pooled upstream DNS connections, and
  the cached transport sessions of every adapter
  reachable from the route table or a proxy provider (mux / smux / yamux /
  h2mux, Hysteria2 QUIC, AnyTLS, the Snell reuse pool, kcptun). Clients
  reconnect and the redials are bound; a request in flight on a flushed
  session fails. One info line logs the counts
  (`Outbound interface binding changed: closed …`).

The flush has known gaps. It does not run when the pre-install failed
(the listener's own install then binds only what is opened afterwards),
and leaving global scope is not flagged (it removes the routes old
sockets could loop on). It cannot reach an external SIP003 plugin's
upstream sockets (a separate process) or the AnyTLS fallback dialer used
when no dial bridge is installed. Idle DNS connections pooled by
resolvers other than the live one are retired but only closed on their
pool's next use (an idle socket sends nothing). TLS session and
VLESS-encryption ticket caches hold no sockets and are kept.

Non-global candidates (`auto-route: fake-ip`/`false`, TUN disabled)
install nothing. A pre-install failure is not fatal — it is logged at
debug and the listener retries before installing routes, failing closed as
at startup.

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
