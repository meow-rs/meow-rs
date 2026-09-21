<div align="center">
  <img src="https://meow-rs.github.io/meow-rs/logo.png" alt="meow-rs — a ginger cat peeking over a wall" width="160">
</div>

# meow-rs

A high-performance Rust implementation of the [mihomo](https://github.com/MetaCubeX/mihomo) (Clash Meta) proxy kernel. Rule-based tunneling with support for multiple proxy protocols, transparent proxy, DNS snooping, a REST API, and a built-in web dashboard.

## Features

### Proxy Protocols
- **Shadowsocks** -- TCP and UDP relay, AEAD and stream ciphers (aes-256-gcm, chacha20-ietf-poly1305, etc.)
- **Trojan** -- TLS 1.2/1.3 (BoringSSL), SNI, optional skip-cert-verify
- **Hysteria2** -- QUIC-based TCP and UDP relay, Salamander obfs, port hopping, down bandwidth auth hint, SNI, skip-cert-verify, and certificate pinning
- **VLESS** -- Plain VLESS and XTLS-Vision splice; TLS, WebSocket, gRPC, H2, HTTPUpgrade transports
- **VMess** -- AEAD VMess outbound with TCP/WebSocket transports
- **HTTP** -- HTTP CONNECT outbound proxy with optional TLS and basic auth
- **SOCKS5** -- SOCKS5 outbound proxy with optional TLS and auth
- **Snell** -- v3/v4/v5 TCP, UDP-over-TCP, optional HTTP/TLS obfs; v4/v5 connection reuse
- **AnyTLS** -- AnyTLS outbound (`anytls` feature; in the `full` bundle, so the release binaries include it)
- **Direct** -- Direct connection to destination
- **Reject** -- Drop connections (with configurable behavior)

### TLS & Privacy
- **ECH (Encrypted Client Hello)** -- DNS-based ECH config fetching from HTTPS/SVCB records; BoringSSL backend (`boring-tls` feature)
- **uTLS Fingerprinting** -- Chrome, Firefox, Safari, iOS, Android, Edge profiles to bypass TLS fingerprint detection
- **BoringSSL** is the single crypto library for the whole app. Every proxy handshake, health check, DoT/DoH upstream, internal HTTP(S) fetch (uTLS fingerprints and ECH included), and the Hysteria2 QUIC transport link one vendored BoringSSL. rustls is not used at runtime at all

### Proxy Groups
- **Selector** -- Manual proxy selection via REST API or web UI
- **URLTest** -- Automatic selection based on latency with tolerance threshold
- **Fallback** -- Automatic failover to first alive proxy
- **LoadBalance** -- Round-robin or consistent-hashing distribution
- **Relay** -- Chained proxy tunneling through multiple hops

### Rule Engine
| Rule | Example | Description |
|------|---------|-------------|
| DOMAIN | `DOMAIN,google.com,Proxy` | Exact domain match |
| DOMAIN-SUFFIX | `DOMAIN-SUFFIX,google.com,Proxy` | Domain and subdomains |
| DOMAIN-KEYWORD | `DOMAIN-KEYWORD,google,Proxy` | Substring match |
| DOMAIN-REGEX | `DOMAIN-REGEX,^ads?\.,Proxy` | Regex pattern |
| DOMAIN-WILDCARD | `DOMAIN-WILDCARD,*.example.com,Proxy` | Wildcard domain pattern |
| IP-CIDR | `IP-CIDR,10.0.0.0/8,DIRECT,no-resolve` | Destination IP range |
| IP-SUFFIX | `IP-SUFFIX,0.0.0.1/8,Proxy` | Destination IP suffix bits |
| SRC-IP-CIDR | `SRC-IP-CIDR,192.168.0.0/16,DIRECT` | Source IP range |
| SRC-GEOIP | `SRC-GEOIP,CN,DIRECT` | Source GeoIP lookup |
| IP-ASN | `IP-ASN,15169,Proxy` | Destination ASN lookup |
| DST-PORT | `DST-PORT,80,443,8080,Proxy` | Destination port(s) |
| SRC-PORT | `SRC-PORT,1234,DIRECT` | Source port(s) |
| NETWORK | `NETWORK,udp,Proxy` | TCP or UDP |
| PROCESS-NAME | `PROCESS-NAME,curl,DIRECT` | Process name |
| PROCESS-PATH | `PROCESS-PATH,/usr/bin/curl,DIRECT` | Process path |
| GEOIP | `GEOIP,CN,DIRECT,no-resolve` | MaxMind GeoIP lookup |
| GEOSITE | `GEOSITE,cn,DIRECT` | MetaCubeX `.mrs` geosite database |
| RULE-SET | `RULE-SET,ads,REJECT` | Rule provider lookup |
| DSCP | `DSCP,46,Proxy` | IP DSCP field |
| IN-PORT | `IN-PORT,7890,Proxy` | Inbound listener port |
| IN-NAME | `IN-NAME,mixed,Proxy` | Inbound listener name |
| IN-TYPE | `IN-TYPE,SOCKS5,Proxy` | Inbound listener protocol |
| IN-USER | `IN-USER,alice,Proxy` | Authenticated inbound user |
| UID | `UID,1000,DIRECT` | Process UID (Linux) |
| SUB-RULE | `SUB-RULE,LOCAL-BYPASS` | Named rule subset |
| MATCH | `MATCH,Proxy` | Catch-all fallback |

Logic composition rules (AND, OR, NOT) are also supported for combining conditions.

### DNS
- UDP DNS server with configurable listen address
- Main + fallback nameserver groups
- Response caching and in-flight request deduplication
- **DNS snooping** -- reverse IP→domain lookup table for transparent proxy hostname recovery

### Inbound Listeners
- **Mixed** -- Auto-detects HTTP or SOCKS5 on a single port
- **HTTP Proxy** -- HTTP CONNECT and plain HTTP forwarding
- **SOCKS5** -- SOCKS5 with optional authentication
- **Transparent Proxy (TProxy)** -- Kernel-level traffic interception via nftables (Linux) or pf (macOS)
- **TUN / Wintun** -- L3 inbound (`tun:`). On Windows this is a [Wintun](https://www.wintun.net/) adapter and is the transparent-proxy path; official Windows zips ship `wintun.dll` beside `meow.exe`, and the binary also embeds a copy to extract if the sidecar is missing

### Transparent Proxy
Intercept local traffic without per-app proxy configuration.

- **Windows**: Wintun TUN adapter (`tun:`). Requires an elevated process and `wintun.dll` next to `meow.exe` (included in official zips). Fake-IP DNS capture; see [docs/tun.md](docs/tun.md).
- **Linux / macOS**: nftables redirect (Linux) or pf anchor (macOS) via `tproxy-port`
- **Loop avoidance (tproxy)**: SO_MARK on outbound DIRECT sockets (Linux), UID-based bypass (macOS), plus IP bypass for upstream proxy servers
- **SNI extraction**: Peek at TLS ClientHello to recover hostname for HTTPS traffic
- **DNS snooping**: Reverse IP→domain lookup from recent DNS queries for non-TLS traffic
- **RAII firewall guard**: tproxy rules automatically cleaned up on shutdown (SIGINT/SIGTERM)
- Configurable via `tun:`, `tproxy-port`, `routing-mark`, and `tproxy-sni` in YAML

The built-in firewall transparently proxies the **host's own** traffic. To build a **LAN gateway** that forwards and proxies *other* devices' traffic, see [docs/tproxy-gateway.md](docs/tproxy-gateway.md).

### Web Dashboard

Built-in web UI served at `http://<api-addr>/ui` with:

- **Overview** -- Mode selector, listening ports, live traffic stats
- **Proxies** -- Click-to-switch selector groups, view all proxy group members
- **Subscriptions** -- Add/refresh/delete Clash YAML subscription URLs (auto-cached to disk)
- **Proxy Groups** -- Create/edit/delete selector, url-test, fallback groups
- **Rules** -- Add/delete/reorder rules with drag-and-drop, search/filter

### Subscription Management
- Fetch and import Clash YAML subscriptions (proxies, groups, rules)
- Auto-save to disk -- cached data loads on restart without re-fetching
- Background refresh on configurable intervals
- Multi-pass group resolution for inter-group references

### REST API
| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Greeting (`{"hello":"meow"}`) |
| `/version` | GET | Version info |
| `/proxies` | GET | List all proxies |
| `/proxies/{name}` | GET/PUT/DELETE | Get, switch, or unfix proxy |
| `/proxies/{name}/delay` | GET | Run an on-demand delay probe |
| `/group` | GET | List proxy groups |
| `/group/{name}` | GET | Get group detail |
| `/group/{name}/delay` | GET | Run a group delay probe |
| `/rules` | GET/POST/PUT | List, replace, or update rules |
| `/rules/{index}` | DELETE | Delete rule at index |
| `/rules/reorder` | POST | Reorder rules |
| `/connections` | GET/DELETE | Active connections (GET also supports WS upgrade) |
| `/connections/{id}` | DELETE | Close a connection |
| `/configs` | GET/PATCH/PUT | Get config, patch mode, or reload config |
| `/traffic` | GET | Upload/download statistics (also supports WS upgrade) |
| `/logs` | GET | Runtime log stream (HTTP streaming or WS upgrade) |
| `/memory` | GET | Runtime memory stream (HTTP streaming or WS upgrade) |
| `/metrics` | GET | Prometheus metrics |
| `/dns/query` | GET/POST | Direct DNS query |
| `/dns/results` | GET | DNS cache dump (`?search=`, `?limit=`) |
| `/cache/dns/flush` | POST | Flush DNS cache |
| `/cache/fakeip/flush` | POST | Flush fake-IP mappings |
| `/listeners` | GET | List configured named listeners |
| `/providers/proxies` | GET | List proxy providers |
| `/providers/proxies/{name}` | GET/PUT | Get or refresh a proxy provider |
| `/providers/proxies/{name}/healthcheck` | GET | Run provider health check |
| `/providers/proxies/{provider}/{proxy}` | GET | Get a specific proxy in a provider |
| `/providers/proxies/{provider}/{proxy}/healthcheck` | GET | Run health check for a specific proxy |
| `/providers/rules` | GET | List rule providers |
| `/providers/rules/{name}` | GET/PUT | Get or refresh a rule provider |
| `/api/config/save` | POST | Save running config to disk |
| `/api/subscriptions` | GET/POST | List or add subscriptions |
| `/api/subscriptions/{name}` | DELETE | Delete subscription |
| `/api/subscriptions/{name}/refresh` | POST | Refresh subscription |
| `/api/proxy-groups` | GET/POST | List or create proxy groups |
| `/api/proxy-groups/{name}` | PUT/DELETE | Update or delete proxy group |
| `/api/proxy-groups/{name}/select` | PUT | Switch selector proxy |
| `/ui` | GET | Web dashboard |

### Tunnel
- Three routing modes: **Rule**, **Global**, **Direct**
- Bidirectional TCP relay and UDP NAT session tracking
- Per-connection traffic statistics with connection lifecycle management

## Benchmarks

Side-by-side against upstream Go mihomo v1.19.29 on the same host (Apple M4 arm64, macOS 26.5.2, loopback `127.0.0.1`). Both binaries use identical config: `mode: direct`, SOCKS5 listener on port 17890, DNS disabled. Reproduce with `bash bench.sh` (auto-downloads the latest Go mihomo release).

| Metric | mihomo (Go) v1.19.29 | meow-rs v0.20.1 | Delta |
|--------|-------------|--------------------|-------|
| Binary size (stripped) | 41.2 MB | **8.6 MB** | **−79%** |
| RSS idle | 29.6 MB | **9.9 MB** | **−67%** |
| RSS under load (peak) | 41.0 MB | **13.5 MB** | **−67%** |
| TCP throughput, 64 MB×1 | 31.30 Gbps | 19.07 Gbps | −39% |
| TCP throughput, 1 MB×10 | 35.77 Gbps | 18.86 Gbps | −47% |
| TCP throughput, 4 KB×10000 | 2.14 Gbps | 1.99 Gbps | −7% |
| Latency p50 (connect + 1 B echo) | 135 µs | **130 µs** | **−4%** |
| Latency p99 | 198 µs | 232 µs | +17% |
| Connections/sec (10 s, concurrency 64) | 711 /s | 714 /s | ±0% |

Per-metric medians of three `bash bench.sh` runs; numbers will vary with host load. Loopback bulk-transfer throughput measures per-proxy CPU overhead, not real-network throughput — both kernels saturate multi-Gbps links with headroom. For the full methodology, three-run-median protocol, and workload definitions (W1–W5), see [ADR-0006](docs/adr/0006-m2-benchmark-methodology.md) and [docs/benchmarks/index.md](docs/benchmarks/index.md).

## Architecture

```mermaid
flowchart TD
    inbound["Inbound listeners<br/>Mixed / HTTP / SOCKS5 / TProxy"] --> tunnel["Tunnel<br/>routing, relay, connection stats"]
    api["REST API + Web UI<br/>Axum"] --> tunnel
    api --> runtime["Runtime state<br/>config, subscriptions, proxy groups, rules"]
    runtime --> tunnel
    tunnel <--> dns["DNS resolver<br/>cache, fake-IP, policy, snooping"]
    tunnel --> rules["Rule engine<br/>linear / indexed / IR matchers"]
    rules --> outbounds["Proxy adapters and groups<br/>SS, Trojan, VLESS, VMess, Snell, Hysteria2, Direct, Reject"]
    outbounds --> remote["Remote server / DIRECT"]
```

11 workspace crates with clear separation of concerns:

| Crate | Purpose |
|-------|---------|
| `meow-common` | Core traits and types (ProxyAdapter, Rule, Metadata) |
| `meow-trie` | Domain trie for efficient pattern matching |
| `meow-transport` | TLS (BoringSSL), WebSocket, gRPC, H2, HTTPUpgrade layers |
| `meow-proxy` | Proxy protocol implementations and groups |
| `meow-rules` | Rule matching engine and parser |
| `meow-dns` | DNS resolver, cache, DNS snooping, server |
| `meow-tunnel` | Core routing, TCP/UDP relay, statistics |
| `meow-listener` | Inbound protocol handlers (Mixed/HTTP/SOCKS5/TProxy) |
| `meow-config` | YAML configuration parsing, subscription fetcher, config persistence |
| `meow-api` | REST API (Axum) + embedded web UI |
| `meow-app` | CLI entry point |

## Quick Start

### Build

Requires Rust 1.88+ (the workspace pins `rust-version = "1.88"` and CI enforces it via a dedicated MSRV job).

```bash
cargo build --release
```

### Run

```bash
# Copy the example config and edit it
cp config.example.yaml config.yaml
# Edit config.yaml with your proxy servers...

# Run
./target/release/meow -f config.yaml

# Test config validity
./target/release/meow -f config.yaml -t
```

### Install as system service

**Linux (systemd):**

```bash
sudo ./target/release/meow install -f /path/to/config.yaml

# Manage the service
sudo systemctl status meow
sudo systemctl restart meow
sudo journalctl -u meow -f

# Uninstall
sudo ./target/release/meow uninstall
```

**Windows (Service Control Manager):**

Open PowerShell as Administrator, then run:

```powershell
# Install, enable automatic startup, and start the service
.\target\release\meow.exe install -f 'C:\path\to\config.yaml'

# Optional: pin the meow resource/cache home explicitly. The global -d flag
# must appear before the install subcommand.
.\target\release\meow.exe -d 'D:\meow-data' install -f 'C:\path\to\config.yaml'

# Check status
.\target\release\meow.exe status
Get-Service meow

# Manage the service
Stop-Service meow
Start-Service meow
Restart-Service meow

# List the daily rolling logs (the seven newest files are retained)
Get-ChildItem "$env:ProgramData\meow\logs\meow.*.log"

# Follow the newest log
$log = Get-ChildItem "$env:ProgramData\meow\logs\meow.*.log" |
  Sort-Object LastWriteTime | Select-Object -Last 1
Get-Content $log.FullName -Wait

# Uninstall
.\target\release\meow.exe uninstall
```

Installation keeps using the configuration file at the path passed to `-f`,
starts the service immediately, and configures it to start automatically with
Windows. A relative `-f` follows the same rule as a direct run: it is resolved
under `-d` when a home directory is given, otherwise under the current
directory. Running `install` again updates the registered binary/configuration
and restarts the service. When `-d` is omitted, the installer resolves and
records the same default meow home used by a normal CLI launch (for example,
`E:\test\meow` when launched from `E:\test`); the selected path is printed as
`Home` after installation. The service runs as LocalSystem, so that account must
have read/write access to the configuration path and the selected Home. After
upgrading from an older service build, run `install` again to refresh the SCM
launch arguments. Uninstalling preserves both the configuration and the logs.

Security notes:

- The service executes the binary at its install-time location as LocalSystem
  on every boot. Copy `meow.exe` to a directory writable only by
  administrators (for example, `C:\Program Files\meow`) and run `install` from
  there, rather than registering a binary inside a user-writable directory.
- `%ProgramData%\meow\logs` inherits the default ProgramData ACLs, so log
  files (which include destination hosts of proxied connections) are readable
  by all local users. Tighten the ACL on `%ProgramData%\meow` if that matters
  on a shared machine.

**macOS (launchd user agent):**

```bash
./target/release/meow install -f /path/to/config.yaml

# Config is copied to ~/Library/Application Support/meow/config.yaml
# Logs are written to ~/Library/Logs/meow/

# Check status
./target/release/meow status

# View logs
tail -f ~/Library/Logs/meow/meow.log

# Uninstall
./target/release/meow uninstall
```

**OpenWrt (opkg + LuCI):**

Official `.ipk` packages for aarch64 routers — including a
`luci-app-meow` that embeds the built-in web panel in LuCI — are attached
to every [release](https://github.com/meow-rs/meow-rs/releases). See
[docs/openwrt.md](docs/openwrt.md).

### Open the Web UI

After starting, open your browser to:

```
http://127.0.0.1:9090/ui
```

From the **Subscriptions** tab you can add a Clash subscription URL to import proxies, groups, and rules automatically.

### Use the Proxy

```bash
# HTTP proxy
curl --proxy http://127.0.0.1:7890 https://ipinfo.io

# SOCKS5 proxy
curl --proxy socks5://127.0.0.1:7890 https://ipinfo.io

# Set as system proxy (macOS)
export https_proxy=http://127.0.0.1:7890
export http_proxy=http://127.0.0.1:7890
```

### Example Configuration

```yaml
mixed-port: 7890
mode: rule
log-level: info

# Transparent proxy (requires root/sudo)
# tproxy-port: 7893
# tproxy-sni: true
# routing-mark: 9527

external-controller: 127.0.0.1:9090

dns:
  enable: true
  listen: 127.0.0.1:1053
  nameserver:
    - 8.8.8.8
  fallback:
    - 8.8.4.4

proxies:
  - name: my-ss
    type: ss
    server: 1.2.3.4
    port: 8388
    cipher: aes-256-gcm
    password: "secret"
    udp: true

  - name: my-trojan
    type: trojan
    server: 5.6.7.8
    port: 443
    password: "secret"
    sni: example.com
    skip-cert-verify: false

  - name: my-snell
    type: snell
    server: ss.example.com
    port: 8443
    psk: "your-psk"
    version: 3
    udp: true
    obfs-opts:
      mode: http
      host: /

  - name: my-hy2
    type: hysteria2
    server: hy2.example.com
    port: 443
    ports: "443,8443-8445"
    hop-interval: 30
    password: "secret"
    sni: hy2.example.com
    skip-cert-verify: false
    udp: true
    up: "100 Mbps"
    down: "100 Mbps"
    obfs: salamander
    obfs-password: "obfs-secret"

proxy-groups:
  - name: Proxy
    type: select
    proxies: [my-ss, my-trojan, my-snell, my-hy2]

  - name: Auto
    type: url-test
    proxies: [my-ss, my-trojan, my-snell, my-hy2]
    url: http://www.gstatic.com/generate_204
    interval: 300

rules:
  - DOMAIN-SUFFIX,local,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - DOMAIN-SUFFIX,google.com,Proxy
  - MATCH,Proxy
```

See [`config.example.yaml`](config.example.yaml) for a full annotated example.

## Testing

Dashboard tests run the shipped HTML in Chromium against an isolated simulated
controller, covering navigation, editing, authentication, error handling, and
live traffic. They do not access a running meow instance or real subscriptions.
The same suite runs in the `dashboard` CI job; failures retain Playwright traces.

```bash
cd tests/dashboard
npm ci
npx playwright install chromium
npm test
```

The dependency-free traffic lifecycle regression tests can also run separately:

```bash
node --test crates/meow-api/tests/ui_test.cjs
```

```bash
# All unit tests
cargo test --lib

# Rules tests (78 tests covering all rule types)
cargo test --test rules_test

# API and config persistence tests (54 tests)
cargo test --test api_test
cargo test --test config_persistence_test

# Trojan integration tests (embedded mock server, no external deps)
cargo test --test trojan_integration

# Hysteria2 Docker integration tests (requires Docker)
MEOW_REQUIRE_DOCKER=1 cargo test -p meow-proxy --features hysteria2 --test hysteria2_integration -- --nocapture

# Shadowsocks integration tests (requires ssserver)
cargo install shadowsocks-rust --features "stream-cipher aead-cipher-2022" --locked
cargo test --test shadowsocks_integration

# Transparent proxy end-to-end tests (requires Docker)
bash tests/test_tproxy_qemu.sh
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). In short: meow-rs is a client-only
kernel (no server-side features), new features and config keys should follow
mihomo mainline, and every PR must pass the full CI test bar and respect the
ADRs in [`docs/adr/`](docs/adr/).

## License

MIT — Copyright (c) 2026 Max Lv. See [LICENSE](LICENSE).
