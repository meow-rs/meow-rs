# meow on OpenWrt

Official `.ipk` (opkg) and `.apk` (apk-tools v3, OpenWrt 25.12+) packages for
aarch64 OpenWrt devices are attached to every
[GitHub release](https://github.com/madeye/meow-rs/releases) (issues
[#284](https://github.com/madeye/meow-rs/issues/284) and
[#466](https://github.com/madeye/meow-rs/issues/466)):

| Package | Architectures |
|---------|---------------|
| `meow_<ver>_<arch>.ipk` | `aarch64_generic`, `aarch64_cortex-a53`, `aarch64_cortex-a72`, `aarch64_cortex-a76` |
| `luci-app-meow_<ver>_all.ipk` | any (LuCI app, architecture-independent) |
| `meow_<ver>-r1_<arch>.apk` | same architectures as the ipk |
| `luci-app-meow_<ver>-r1_all.apk` | any (LuCI app, architecture-independent) |

OpenWrt 25.12 and later replaced opkg with apk; use the `.apk` files there and
the `.ipk` files on 24.10 and older. Both formats carry the same payload,
maintainer scripts and config-file handling. Note the apk version suffix:
apk spells the package revision `-rN` where opkg uses `-N`.
The binaries are fully static musl builds, so they have no library
dependencies beyond OpenWrt's base system. All aarch64 packages contain
the same `aarch64` binary — only the opkg `Architecture:` label differs so
that `opkg` accepts the package on your device.

Rolling alpha `.ipk`s and `.apk`s from `main` are published on the
[`Prerelease-Alpha`](https://github.com/madeye/meow-rs/releases/tag/Prerelease-Alpha)
prerelease (unstable). Their version is `<last-release>-alpha.<YYYYMMDDHHMM>.<sha7>-1`,
which opkg orders above the last stable release and below the next one;
the `.apk`s use `<last-release>_git<YYYYMMDDHHMM>-r1`, which apk orders the
same way. They cover the same architectures as above.

Feature note: release binaries use the default meow-app feature set
(`full` + `boring-tls`), so ECH and uTLS fingerprinting are included.

32-bit arm / MIPS OpenWrt packages are not published: `boring-sys` does not
build for those targets. Cross-build from source with
`--no-default-features --features full` if you need them without BoringSSL.

Find your device's architecture with:

```sh
. /etc/openwrt_release; echo "$DISTRIB_ARCH"
```

For example, a Raspberry Pi 4 OpenWrt image is typically
`aarch64_cortex-a72`. If your architecture is not in the table but is a
superset of one that is, the closest smaller package works — the binary
makes no assumptions beyond the aarch64 baseline. Devices of other
families (32-bit arm, mips, x86) can use a self-built static binary or,
for `x86_64`, the `x86_64-unknown-linux-musl` release tarball as-is.

## Install

Transfer the packages to the device and install.

OpenWrt 24.10 and older (opkg):

```sh
opkg install ./meow_<ver>_<arch>.ipk
# optional, for the LuCI integration:
opkg install ./luci-app-meow_<ver>_all.ipk
```

OpenWrt 25.12 and newer (apk). The packages are unsigned, so apk needs
`--allow-untrusted`:

```sh
apk add --allow-untrusted ./meow_<ver>-r1_<arch>.apk
# optional, for the LuCI integration:
apk add --allow-untrusted ./luci-app-meow_<ver>-r1_all.apk
```

Upgrades work the same way (`apk add --allow-untrusted ./newer.apk`). Edited
`/etc/config/meow` and `/etc/meow/config.yaml` are kept; the packaged copy is
written next to them as `*.apk-new`. `apk del meow` leaves the config files in
place; `apk del --purge meow` removes them too.

The `meow` package installs:

- `/usr/bin/meow` — the static binary
- `/etc/init.d/meow` — procd init script (enabled on install, but the
  service is **not started** until you set `enabled` to `1`)
- `/etc/config/meow` — UCI service settings (enable flag, config path,
  working directory, panel port)
- `/etc/meow/config.yaml` — default meow configuration (mixed HTTP/SOCKS5
  proxy on `:7890` for the LAN, REST API + web panel on `:9090`,
  rule mode with `MATCH,DIRECT`)

Both `/etc/config/meow` and `/etc/meow/config.yaml` are conffiles: opkg
preserves your edits across upgrades.

LuCI's delegated file permissions are confined to `/etc/meow/config.yaml` and
its validation scratch files; the managed service uses these fixed paths. Custom paths require running meow
manually over SSH.
Validation uses a fixed-argument helper, and OpenWrt disables external SIP003
executables at both validation and runtime (built-in plugins remain supported).
A random API secret is generated at installation, preserving existing secrets
on upgrade. Clearing it restricts the API to loopback; remote panel access then
requires setting a secret again. HTTP provider payloads absent from the cache
are deferred during `-t`, including strict validation; cached rule payloads and
inline definitions are still checked. ECH DNS lookup is deferred to startup.

## Configure and start

Edit `/etc/meow/config.yaml` (add your proxies, groups and rules — see
[config.example.yaml](../config.example.yaml)), then:

```sh
uci set meow.main.enabled='1'
uci commit meow
/etc/init.d/meow start
```

The init script validates the config (`meow -t`) before starting and logs a
message via `logger` if validation fails. procd restarts the service when
either `/etc/config/meow` or the YAML config changes, and respawns it if it
crashes.

## LuCI app

`luci-app-meow` adds **Services → meow**. Runtime data comes from the
meow REST API through authenticated LuCI RPC (including on HTTPS pages), and proxy management is the built-in web panel, so LuCI does
not reimplement a dashboard:

- **Overview**: service state and version, transparent-proxy state, proxy
  mode switch (`PATCH /configs`) with a one-line explanation of each mode,
  current speed, traffic totals and active connections (`/connections`).
  Start/Stop/Restart buttons match the service state and report failures.
  When meow is disabled a banner offers **Enable and start**; when it is
  enabled but stopped, the banner points to the Log.
- **Panel**: meow's built-in web dashboard (`http://<router>:<panel_port>/ui`)
  embedded in LuCI, covering proxy selection, subscriptions, groups and
  rules. The API secret is passed in the URL fragment (`#token=`), so the
  panel works without typing it again.
- **Configuration**: raw YAML editor. Edits are validated with `meow -t`
  before they replace the file. Saving explicitly restarts a running service;
  a stopped service stays stopped. Restart failures are reported separately.
  Validation uses cached rule providers and local geodata without downloading;
  missing databases are deferred to normal startup, so first-time setups can
  still validate. Existing local databases are checked normally.
  A status line shows lines, size and unsaved changes; **Revert** restores
  the saved file, Tab indents with two spaces, Ctrl/Cmd+S saves, and leaving
  the page with unsaved edits asks first.
- **Clients**: known LAN clients (hostname, IP, MAC) with a per-client proxy
  bypass, plus opt-in ARP-based client steering (see below).
- **Settings**: Basic/Advanced tabs for the service (enable, panel port,
  panel password; config path and working directory under Advanced) and the
  transparent proxy (on/off with live status, TCP+UDP or TCP only, LAN
  interface, DNS handling; ports, IPv6 and bypass networks under Advanced).
  "Proxy IPv6" is offered only in TCP-only mode, the one mode that supports it.
- **Log**: meow's entries from the system log, oldest first and following the
  newest entry; text filter, level filter (all / warnings and errors / errors),
  errors in red and warnings in orange, Pause/Resume, and Download.

`panel_port` and `secret` are authoritative: the init script passes them to
meow as `--ext-ctl 0.0.0.0:<panel_port>` and `--secret <secret>`, overriding
`external-controller` / `secret:` in the YAML. OpenWrt's default firewall
blocks WAN-side access; set a secret if untrusted hosts share your LAN. If
LuCI is served over HTTPS, the Panel view offers a new-tab link instead of
embedding mixed content. Overview API requests stay on LuCI's authenticated
origin; the packaged curl helper contacts only the router's loopback API.

## Transparent proxy (gateway / side router)

Enable **Settings → Transparent proxy** (or `uci set meow.tproxy.enabled=1`).
The default mode needs `kmod-nft-socket` and `kmod-nft-tproxy`; install them
with `opkg install` (`apk add` on newer OpenWrt). Startup checks the generated
rules and logs an install hint when kernel support is missing.
`/usr/share/meow/gateway.sh` then loads an nftables table
`inet meow_gateway` for traffic arriving on the chosen LAN interface:

- **`mode tproxy`** (default): nat `REDIRECT` for **TCP** plus kernel TPROXY
  for **UDP**. TCP is redirected (not TPROXY'd) because meow's TCP listener
  recovers the original destination via `SO_ORIGINAL_DST`, which only the
  conntrack DNAT that `REDIRECT` creates populates; a TPROXY'd TCP flow leaves
  no conntrack entry, so its destination resolves to the listener's own
  address and meow dials itself in a loop. UDP has no `REDIRECT` equivalent
  and a real `IP_TRANSPARENT` listener, so a mangle-prerouting `tproxy to
  :<tproxy_port>` rule marks datagrams `0x2333` and a policy route (`ip rule
  fwmark 0x2333 lookup 233`, `local default dev lo table 233`) delivers them.
- **`mode redirect`**: nat `REDIRECT`, TCP only (no UDP).
- **Loop avoidance**: both chains `return` early on meow's own outbound, which
  carries the `routing-mark` (`9527` = `0x2537`) as an SO_MARK, so proxied
  traffic is never re-captured. The firewall mark (`0x2333`) and `routing-mark`
  are deliberately different; keep `routing-mark` in the YAML matching the
  `ROUTING_MARK` in `gateway.sh`.
- **DNS hijack**: LAN UDP DNS (port 53, any resolver) is redirected to meow's
  resolver (`dns_port`, default 1053), which is needed for fake-ip.
- Private, reserved, multicast and router-local destinations bypass the
  proxy. Add more with `list bypass`.

Saving **Settings** synchronizes the selected local YAML before saving UCI:

- Panel port and API secret are written to `external-controller` and `secret`
  (clearing the secret clears it in YAML too).
- Enabling transparent proxy creates or updates the `tproxy-lan` listener with
  the selected port, `firewall: false`, and `udp: true` only in TPROXY mode.
  It replaces the router-local `tproxy-port` shorthand and sets
  `routing-mark: 9527` to match the gateway firewall bypass mark.
- DNS hijacking enables the resolver and sets `dns.listen` to
  `0.0.0.0:<DNS port>`. Loopback `proxy-server-nameserver` entries pointing
  at the old DNS listener port are moved to the new port as well. Other
  upstream DNS settings are retained.
- Disabling transparent proxy removes only `tproxy-lan`; custom listeners,
  proxies and rules remain intact. Disabling DNS hijacking stops the firewall
  redirect but leaves the resolver configured for meow's own use.
- IPv6 capture uses a dual-stack TCP listener in REDIRECT mode. IPv6 with
  UDP TPROXY is rejected because that listener supports only IPv4.

The candidate YAML is checked with `meow -t` before replacement. Validation
and upload errors prevent the UCI save; a subsequent UCI save failure restores
YAML. YAML is written on **Save**; **Save & Apply** also applies UCI and restarts
the service. The Configuration tab reapplies these same settings when saving
an imported subscription, so imports cannot remove the gateway listener.
Comments, anchors and unrelated settings are retained by the YAML document
editor. Avoid editing the same configuration in multiple browser sessions.

Direct CLI changes to UCI still require matching YAML; this synchronization is
performed by the LuCI views. The shipped default YAML already contains the
matching gateway listener and DNS resolver.

**Side-router setup:** give OpenWrt a static address on the existing LAN,
with the main router as its gateway and DNS. Disable its DHCP server and RA,
and enable masquerading on the `lan` zone. Then steer clients to the OpenWrt
address by one of:

- a per-device **gateway + DNS** set on the client, or a DHCP
  reservation/option on the main router (cleanest — no spoofing); or
- **ARP client steering** (below), which needs no client or main-router change.

## Clients tab: bypass and ARP steering

**Services → meow → Clients** lists the LAN clients this router knows about —
DHCP leases, static leases (`/etc/config/dhcp` hosts) and neighbours — with
their hostname, IPv4/IPv6 addresses, MAC and source.

### Bypassing the proxy per client

Tick **Bypass** for a client and Save & Apply: its traffic is no longer
captured by the transparent proxy **and** its DNS is no longer hijacked to
meow (so fake-ip answers never reach it). Clients are matched by MAC, so a new
DHCP lease keeps the setting. The list is stored as
`list bypass_mac '<MAC>'` in the `tproxy` section of `/etc/config/meow`;
`gateway.sh` loads it into the nftables set `inet meow_gateway bypass_src`,
checked first in both capture chains. CLI equivalent:
`uci add_list meow.tproxy.bypass_mac=<MAC>`, `uci commit meow`,
`/etc/init.d/meow restart`.

### Selecting clients by ARP (advanced, opt-in)

Steering lives in the collapsed **ARP client steering (advanced)** section;
enabling it reveals a **Steer** column (a client is either bypassed or
steered, never both). For each ticked client, the `meow-arp` service (`arp-hijack.sh`)
periodically sends it a unicast ARP reply announcing this router as the
client's gateway, so the client's off-LAN traffic arrives here and is
transparently proxied — without touching the client or the main router's DHCP.

This is **ARP spoofing**. It is appropriate only for devices you administer on
a network you control, and it is **off by default**: the `arp_hijack` section
of `/etc/config/meow` starts disabled and empty, so no device is ever affected
until you enable steering and tick it. Untick a client (Save & Apply) to
release it; its ARP cache relearns the real gateway once meow stops announcing.
Steering uses meow's built-in Linux `arp-reply` command. Each Ethernet and
ARP target address is the selected client's MAC; no broadcast replies or
external `arping` implementation are used. Stopping steering is passive:
clients return to the real gateway when their ARP entries expire.

Notes and limits:

- It is a continual re-announcement (`interval`, default 2s) racing the real
  router's own ARP; a network with Dynamic ARP Inspection or port security
  will drop it.
- `gateway` (empty = the interface's real gateway) is the IP announced.
- CLI: `uci set meow.arp.enabled=1`, `uci add_list meow.arp.client=<MAC>`,
  `uci commit meow`, `/etc/init.d/meow-arp restart`.
- Prefer the DHCP-option approach where the main router supports it: it is
  reliable, survives reboots, and is not a spoofing technique.

### Running OpenWrt as a Docker side router

`openwrt/docker/side-router.sh` does all of this for an OpenWrt rootfs
container attached to the physical LAN through a macvlan network in bridge
mode:

```sh
PARENT=eth0 SUBNET=192.168.1.0/24 LAN_GW=192.168.1.1 OPENWRT_IP=192.168.1.250 \
    openwrt/docker/side-router.sh up dist/     # dist/ holds the two ipks
```

It loads the needed nftables kernel modules on the host, creates the
container, provisions the side-router UCI config and LuCI, and installs the
ipks. It also adds a host-side macvlan shim so the Docker host itself can
reach the container.

## Building ipks and apks yourself

`openwrt/build-ipk.sh` assembles ipks from any static musl build without
the OpenWrt SDK:

```sh
cargo zigbuild --release --target aarch64-unknown-linux-musl --bin meow
openwrt/build-ipk.sh meow \
    --binary target/aarch64-unknown-linux-musl/release/meow \
    --version 0.16.0-1 --arch aarch64_generic --outdir dist
openwrt/build-ipk.sh luci --version 0.16.0-1 --outdir dist
```

`openwrt/build-apk.sh` is the apk counterpart with the same arguments. It
needs apk-tools 3 (`apk mkpkg`) and root, and takes the apk-style
`X.Y.Z-rN` version:

```sh
# one-time: fetch a pinned static apk-tools 3 (Linux x86_64 / aarch64)
openwrt/install-apk-tools.sh ~/.cache/apk-tools
sudo APK=$HOME/.cache/apk-tools/apk openwrt/build-apk.sh meow \
    --binary target/aarch64-unknown-linux-musl/release/meow \
    --version 0.16.0-r1 --arch aarch64_generic --outdir dist
sudo APK=$HOME/.cache/apk-tools/apk openwrt/build-apk.sh luci --version 0.16.0-r1 --outdir dist
```

On macOS, run it inside an Alpine container (`apk add bash`, apk-tools 3 is
the default `apk` in current Alpine).

## End-to-end test

`tests/test_openwrt_docker.sh` is a multi-container **side-router** test: it
builds an OpenWrt router container that bridges an internal LAN to a WAN, puts
an HTTP + UDP-echo origin on the WAN and two clients on the LAN (whose only
route out is through the router), enables meow's transparent proxy, and asserts
the full data path — TCP **and** UDP TPROXY (each client's flow shows up in
meow's log), DNS hijack (fake-ip answer), the REST API + built-in panel, and
that the LuCI Clients view + ACL ship. It is hermetic (the origin is on an
RFC 5737 test-net so it is actually proxied, not bypassed as a private range)
and needs no physical NIC or real LAN.

The CI `openwrt` job runs this suite, including package installation, shipped
config validation, mixed-port HTTP relay, service stop/restart, and LuCI: `rpcd`
loads the `luci-app-meow` ACL group and a root `ubus` login expands the meow
file/exec grants, and the Clients view is registered in the on-device menu.

```sh
# requirements: docker, cargo-zigbuild + zig (or MEOW_BINARY), and the
# Docker host kernel with nftables TPROXY support.
# MEOW_REQUIRE_DOCKER=1 makes missing prerequisites fail (used in CI).
bash tests/test_openwrt_docker.sh
# KEEP=1 leaves the containers/networks up for inspection.
```

`tests/test_luci_meow.sh` statically validates the `luci-app-meow` package with
no device or container: it parses every view (the way LuCI loads them), checks
the menu and ACL JSON, and cross-checks the wiring — every menu view has a view
file and vice-versa, `require tools.*` modules exist, and the ACL's exec grants
for meow's own scripts reference files the package actually ships and installs.

```sh
# requirements: node + jq (SKIPs otherwise)
bash tests/test_luci_meow.sh
```

## Not yet provided

- An opkg feed (per-release ipks only; `opkg update`-able feed may come
  later once this stabilizes).
- An apk repository/feed (per-release `.apk` files only; they are unsigned).
- 32-bit arm / mips release ipks — release artifacts require the default
  `full` + `boring-tls` feature set; boring-sys does not build for those
  targets. Build from source with `--no-default-features --features full`
  if needed.
