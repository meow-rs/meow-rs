# OpenWrt packaging

Packaging sources for the official OpenWrt `.ipk` release artifacts
(issue [#284](https://github.com/madeye/meow-rs/issues/284)).

- `build-ipk.sh` — assembles opkg-format `.ipk` packages from a prebuilt
  static musl binary, without the OpenWrt SDK. Run with no arguments for
  usage.
- `meow/files/` — procd init scripts (`meow.init`, `meow-arp.init`),
  `/etc/config/meow` UCI settings, the default `/etc/meow/config.yaml`,
  `gateway.sh` (transparent-proxy nftables rules for gateway / side-router
  mode: kernel TPROXY or REDIRECT), and `arp-hijack.sh` (opt-in, off-by-default
  ARP-based client steering for the LuCI Clients tab — ARP spoofing, for
  devices you administer only).
- `luci-app-meow/` — LuCI app: `root/` overlays `/` on the device,
  `htdocs/` maps to `/www`. Overview, config editor, clients, settings and log
  views talk to the meow REST API and UCI; the Panel tab embeds the built-in
  web UI served at `/ui` instead of reimplementing a dashboard.
- `docker/side-router.sh` — runs OpenWrt in a Docker container on the LAN
  (macvlan, bridge mode) configured as a side router with meow installed.

Release wiring lives in `.github/workflows/release.yml` (ipk matrix), the
Docker end-to-end test in `tests/test_openwrt_docker.sh`, and user-facing
documentation in [docs/openwrt.md](../docs/openwrt.md).
