# proxy-mux: Connection Multiplexing (sing-mux + Xray Mux.Cool)

Status: sing-mux (smux / yamux / h2mux) and **Xray Mux.Cool**
(`protocol: muxcool`) are fully implemented, unit-tested. sing-mux
applies to VLESS / Trojan / Shadowsocks / VMess outbounds; muxcool
applies to VLESS and VMess (CommandMux signaling in both request
headers). Interop matrix:

- sing-mux ↔ sing-box v1.13.18 (VLESS plaintext / Trojan+TLS / Reality /
  Reality+Vision inbounds with multiplex enabled) works both ways;
- muxcool ↔ local sing-box (plaintext / Reality / Reality+Vision, TCP+UDP)
  works;
- muxcool ↔ **real Xray node** (example-xray-node, VLESS Reality+Vision)
  works — on the same node sing-mux does not interoperate (Xray only speaks
  Mux.Cool).
  (follow-up, closing the mux gap from the gap analysis)
Reference implementations: mihomo Alpha
(adapter/outbound/singmux.go, listener/sing/sing.go), metacubex/sing-mux,
sagernet/sing-mux, sagernet/smux (smux frame format), metacubex/sing v0.5.7
(address codec); Mux.Cool follows xray-core common/mux
(frame.go / writer.go / session.go) and sing-vmess mux.go.

## Goal

Real multiplexing the mihomo way: provide
`smux: {enabled, protocol, max-connections, min-streams, max-streams, padding, statistic, only-tcp}`
(aligned with SingMuxOption) on VLESS / Trojan / Shadowsocks / VMess
outbounds, multiplexing many logical streams over **one physical node
connection** and eliminating the per-stream node TCP+TLS+protocol handshake
cost (measured 500-700ms per new connection @140ms RTT). The legacy `mux:`
key remains accepted for compatibility; configuring both keys warns and prefers the canonical `smux:`.

## Wire Protocols (confirmed field-by-field from the sources)

### 1. Physical connection setup (VLESS / Trojan / SS / VMess)

1. Client TCP(+TLS) to the node and performs the protocol handshake with
   **destination = the reserved mux FQDN** `sp.mux.sing-box.arpa:444`:
   VLESS and VMess carry the address in their request header; Trojan does
   not but writes the reserved FQDN anyway for parity; SS carries no wire
   address at all (the destination is irrelevant to the cipher stream —
   the server detects multiplexing by sniffing the mux request header).
2. The mux request header (see §2) is written **immediately after** the
   handshake, in the same write batch.
3. The server recognizes the mux request header → switches into the mux
   service; the VLESS 2-byte response header (`[version, addons_len]`) is
   **lazily prefixed to the first downstream write** by the server, so the
   client strips it on its first read (meow-rs's `VlessConn` already has
   lazy `response_pending` consumption, which fits naturally).

### 2. Mux request header (protocol negotiation)

| Field | Length | Meaning |
|---|---|---|
| version | u8 | 0 or 1 |
| protocol | u8 | 0=smux, 1=yamux, 2=h2mux (mihomo default h2mux) |
| padding | u8 | present only when version==1; 1=enabled |
| padding_len | u16 BE | only when padding=1; value = 256 + rand(512) |
| padding bytes | n | random padding |

#### 2.1 Padded sessions (`padding: true`)

With the padding flag set, both ends wrap the physical connection in
sing-mux's `paddingConn` (padding.go) **after** the request header and
before the smux / yamux / h2mux session starts; the request header itself
is not framed. The first 16 writes in each direction are framed as

```text
[data_len u16 BE][padding_len u16 BE][data][padding_len bytes]
```

with `padding_len = 256 + rand(512)` (256..=767) and at most 65535 data
bytes per frame (larger writes are split). The reader parses the first 16
frames the same way (a zero-length frame is legal and is not EOF);
everything after the 16th frame passes through unframed. A sing-box
inbound with `multiplex.padding: true` rejects clients that do not pad
("non-padded connection rejected"). meow-rs implements this layer in
`padding.rs` (`PaddingConn`) for the three sing-mux protocols; Mux.Cool
has no padding, so `padding: true` with `protocol: muxcool` is a hard
config error (Class A per
[ADR-0002](../adr/0002-upstream-divergence-policy.md): ignoring it would
silently send the unpadded traffic shape).

### 3. Sessions (one per physical connection, chosen by protocol)

- **smux**: note — sing-mux uses the **sagernet/smux fork**, whose frame
  format differs from upstream xtaci:
  [ver=1][cmd][len u16 LE][stream_id u32 LE][data] (8-byte header,
  little-endian). cmd: SYN=0, FIN=1, PSH=2, NOP=3 (UPD=4 only in v2). v1
  has **no window-update flow control** — the write side splits into
  MaxFrameSize=32768 frames (u16 length cap). Config =
  smux.DefaultConfig() + KeepAliveDisabled=true (Version=1,
  MaxFrameSize=32768, MaxStreamBuffer=64KiB, MaxReceiveBuffer=4MiB).
- **yamux**: hashicorp yamux (interoperates with libp2p rust-yamux);
  StreamClose/OpenTimeout = 5s.
- **h2mux** (mihomo default): sing's custom layer over HTTP/2
  (sing-mux/h2mux.go). Each stream = one CONNECT request to
  https://localhost (no :scheme/:path); request-body DATA frames =
  client→server, response-body DATA frames = server→client. The **server
  flushes the 200 lazily**: the 200 HEADERS go on the wire only with the
  first response-body write, so the client **must not block waiting for
  the 200** — sing-mux uses lateHTTPConn (write side usable immediately,
  read side waits for setup) — meow-rs likewise parses the response lazily
  on the first read with a 5s (TCPTimeout) cap. On stream close sing-box
  sends RST_STREAM(NO_ERROR), treated as a clean EOF (the Go client maps
  it to io.EOF the same way). The sing-box *server* reaps idle h2mux
  sessions after 30s (h2mux.go idleTimeout).

### 4. Per-stream addressing (StreamRequest / StreamResponse)

After opening a stream, the client's first write is the **stream request**
(protocol.go EncodeStreamRequest):
[flags u16 BE][type u8][addr][port u16 BE], flags=0 for TCP (flagUDP=1 for
UDP streams). Socksaddr types: 0x01=IPv4(4B), 0x03=FQDN(len u8 + bytes),
0x04=IPv6(16B). The server reads the address and dials the real target for
that stream.

**Every stream's first downstream write carries a status byte**
(serverConn.Write): [status u8], 0=success; 1=error followed by a varbin
length-prefixed error message. The client strips the status byte on its
first read (sing-mux clientConn.readResponse); meow-rs handles it uniformly
in the MuxStream layer for all three protocols.

**UDP streams**: a stream whose flags set flagUDP(1) is a UDP stream, bound
to the destination in the stream request; afterwards both directions are
[len u16 BE][data] datagram frames (the same framing as meow's VLESS
UDP-over-TCP), with no per-packet addresses. The server handles them via
serverPacketConn. meow-rs's `MuxPacketConn` implements this framing;
`only-tcp: true` routes UDP over the plain non-mux path instead. The
`statistic`/`brutal-opts` fields are not supported yet (each gets a warn
on parse; brutal is Linux-only upstream).

### 5. Client session management (aligned with sing-mux client.go)

- `openStream`: pick the session with the fewest streams among
  `CanTakeNewRequest` sessions; if none, `offerNew` (fresh physical
  connection + handshake + session).
- Bounds: when maxConnections>0, decide by connection count / per-connection
  minStreams; otherwise by global maxStreams.
- Connection failure / closed session → retry at most 2 times; the
  *client* pool evicts zero-stream sessions after a 60s idle timeout
  (meow-rs `IDLE_TIMEOUT`, mirroring sing-mux Service IdleTimeout).
- padding mode uses version=1 and wraps the session in the §2.1 padding
  layer; TCPTimeout=5s caps connection setup.

### 6. Xray Mux.Cool (`protocol: muxcool`, VLESS + VMess)

Mux.Cool is Xray's frame multiplexing protocol (same lineage as
v2ray-plugin's mux) and is **completely unrelated** to sing-mux: there is
**no** mux request header — the session signaling is the VLESS request
header itself.

**Signaling**: the session connection's VLESS request header carries
command = 0x03 (CommandMux) and **omits** the port/address (xray
encoding.go::EncodeRequestHeader skips the address for CommandMux;
sing-vmess vless/protocol.go::ReadRequest likewise skips parsing). The
2-byte VLESS response header `[version, addons_len]` is still consumed
lazily (VlessConn logic unchanged). Under Vision the request header rides
inside the first Vision record together with the first mux frame
(VlessConn::new_mux_deferred, same as the sing-mux path).

**Frame format** (xray common/mux/frame.go, all big-endian):

```text
meta_len   u16 BE    length of the meta block
meta:
  session_id u16 BE  stream id — client-allocated (incrementing from 1),
                      echoed back by the server
  status     u8      1=New 2=Keep 3=End 4=KeepAlive
  option     u8      bit1=Data, bit2=Error
  (New frames, and Keep frames carrying a UDP destination:)
    network u8       1=TCP 2=UDP
    port    u16 BE
    atype   u8       0x01 IPv4 | 0x02 domain | 0x03 IPv6
    address ...      VMess address layout (port first)
payload_len u16 BE   present only when option&Data
payload             payload_len bytes
```

End frames carry no payload_len; KeepAlive frames use sid=0 (unbound). The
server **never opens streams** (responses echo the client's sid). Optional
trailing meta bytes on New frames (xray's fullcone source info, UDP
GlobalID) are not sent by us, and both server implementations discard
unknown trailing meta bytes.

**Stream semantics**:

- TCP streams: New frame (meta-only) opens the stream → Keep+Data frames
  carry data in both directions (≤ 8KiB per frame, matching xray writer.go
  chunking) → End frame (sent on shutdown or drop; EndGuard guarantees
  exactly-once). Server End → clean EOF; with the Error option → error.
- UDP streams: New frame with network=UDP opens the stream; Keep frames in
  both directions carry a **per-datagram destination** in the meta
  (aligned with sing-vmess serverMuxPacketConn); the read side parses the
  source address back out, and frames without an address fall back to the
  stream's bound destination.
- Session: a **single driver task** owns the connection and polls both
  directions from that one task (the same discipline as h2mux's h2 driver)
  — outbound frames go to the driver over a bounded channel (PollSender
  poll-based backpressure), inbound frames are read and demuxed by the
  driver's state machine (bounded 32-deep per-stream channel). **Inbound
  delivery never blocks the driver**: a frame hitting a full queue parks
  (at most one) and pauses the connection read (session-wide flow control,
  TCP window semantics); consumers wake the driver via the space Notify
  whenever they drain a slot (notify_one's permit semantics cover the
  arm-before-check window; an unconditional loop-top retry is the
  fallback). Blocking delivery would deadlock a write-then-read consumer
  (its writes wait on outbound capacity while the driver waits on inbound
  capacity) — a dedicated regression test covers this (1MiB full-duplex
  loop, the old design deadlocks 100%). End frames remove the stream entry
  before the terminal event parks (no stale senders); session ids never
  wrap around (a recycled id would collide with a live stream's frames).
  30s KeepAlive (sid=0).
  **Key lesson (root-caused to the exact mechanism)**: an earlier stream
  write path used a stored future — poll_write returned Pending while a
  write future was in flight, and on completion the future fell through and
  re-framed the **current buffer** (the relay's HalfCopy does not advance
  pos on Pending and re-polls with the same buffer) → the same chunk was
  written twice → duplicated bytes inside the stream → end-to-end TLS record
  desync (bursts of schannel failures with zero protocol-layer errors and
  intact small HTTP responses — extremely stealthy). Plaintext loopback
  writes rarely hit Pending so it never triggered; TLS burst writes often
  did, worst under 12-stream lock contention on one session (100% repro).
  Fix: stream writes enqueue frames to the session driver task (PollSender
  poll-based backpressure, no stored future — duplication is structurally
  impossible); additionally the VlessConn lazy response-header consumption
  became persistent state (same class of cancel-safety hazard). 12-way
  concurrent stress after the fix: 0 failures (local 780/780, real Xray
  612/612).

**Server compatibility**: Xray-core VLESS and VMess inbounds (native);
sing-box / mihomo VLESS and VMess inbounds (sing-vmess
HandleMuxConnection on CommandMux, same frame lineage, no inbound config
needed). Note: the `v1.mux.cool` magic destination (port 666) is the
legacy v2ray address trick — sing-vmess defines it (`MuxDestination`) but
never uses it; modern signaling is the CommandMux byte in the request
header, which is what meow-rs sends.

## meow-rs Architecture Mapping

```
crates/meow-proxy/src/mux/
  mod.rs        Protocol (+MuxCool), MuxClient (session pool + offer/offerNew + idle sweep)
  request.rs    §2 sing-mux request header encode/decode (incl. padding)
  padding.rs    §2.1 PaddingConn: padded-session framing (first 16 frames each way)
  address.rs    §4 stream request codec (flags + sing Socksaddr)
  smux.rs       smux session + stream (sagernet fork frame format, self-implemented)
  yamux.rs      yamux wrapper (on the libp2p yamux crate)
  h2mux.rs      h2mux session + stream (h2 crate: CONNECT stream = bidirectional bodies)
  muxcool.rs    §6 Mux.Cool: frame codec (pure functions) + session + TCP stream + UDP PacketConn
  packet.rs     MuxPacketConn: UDP stream (flagUDP + [len u16 BE][data] datagram frames)
  stream.rs     MuxStreamConn: ProxyConn wrapper (pin-projection of the !Unpin inner stream,
                modeled after anytls AnytlsConn)
```

- Integration points: `vless_adapter::dial_tcp`, `trojan::dial_tcp`,
  `shadowsocks_adapter::dial_tcp` and `vmess::VmessAdapter::dial_tcp` —
  when mux is enabled they call `mux_client.open_stream(dest)` instead of
  dialing a fresh connection; each adapter's `with_mux` builds a
  `DialFn` that performs the plain protocol handshake targeting
  `sp.mux.sing-box.arpa:444` (SS shares its dial state with the mux
  session through an `Arc`-wrapped core so SIP003 plugin handles stay
  alive).
- Config parsing: the canonical `smux:` block (plus legacy `mux:` alias) is
  parsed, default protocol=h2mux matching mihomo; smux/yamux/h2mux all
  implemented; unknown protocols reject the node with meow's warn+skip
  semantics (mihomo hard-errors on the same input).
- Build gating: the `mux` Cargo feature (meow-proxy/meow-config/meow-app,
  on by default, excluded from `minimal`). A no-mux build reading an
  enabled mux block warns that the option was ignored.
- Health checks / URLTest: delay probes over mux streams naturally reuse
  the same session.

## Interop Boundaries (important)

- `protocol: smux|yamux|h2mux` (default h2mux): applies to VLESS /
  Trojan / Shadowsocks / VMess. The server must be sing-box / mihomo
  based with `multiplex` enabled on the matching inbound (a plain
  ss-server does not speak sing-mux). **Xray servers are incompatible** —
  Xray only speaks Mux.Cool; use `protocol: muxcool` (VLESS/VMess) there.
- `protocol: muxcool` (VLESS / VMess): the server is Xray-core, or a
  sing-box / mihomo VLESS / VMess inbound (whose sing-vmess server handles
  CommandMux natively, no inbound config needed). Do not use on Trojan or
  Shadowsocks nodes.
- Both protocol families share one MuxClient pool and the same min/max
  bounds; all protocol differences are contained in the SessionKind arms
  and the with_mux dial closure — zero branching in the adapter layer.
- **Pool defaults**: meow defaults to `max-connections=4, min-streams=4,
  max-streams=4`. mihomo's `smux:` block defaults to `0/0/0`, which makes
  sing-mux apply `minStreams = 8` upstream. A user copying a mihomo config
  with explicit zeros gets one physical connection per stream (mihomo
  semantics); a user relying on implicit defaults gets meow's 4/4/4 pooling
  rather than mihomo's 0/0/0.

## Test Plan

1. Unit: request header/padding codec; padded-session framing (byte-exact
   frames, 16-frame cutoff both ways, u16 chunking, 1-byte split reads,
   Pending-retry writes); Socksaddr codec round trips; smux
   frame codec (wire byte assertions), SYN/FIN/PSH state machine, large
   write frame splitting (in-memory duplex both-ends exercise); MuxClient
   offer/offerNew/min-max bounds and concurrency caps (mock dialer);
   yamux/h2mux concurrent open + echo.
2. Integration (done; scripts under target/e2e/mux-interop/):
   - sing-mux: local sing-box v1.13.18 VLESS (plaintext) / Trojan (TLS) /
     Shadowsocks / VMess inbounds with multiplex enabled — meow curls the
     local websrv through h2mux/smux/yamux with 200, gstatic 204 (h2 +
     http/1.1) and UDP echo round trips; 6 concurrent curls share one
     physical connection. live_singbox_vless_probe (#[ignore]) is kept as
     a repeatable interop regression.
   - muxcool: the same sing-box inbounds (CommandMux needs no inbound
     config) — plaintext VLESS (TCP 204/200 + UDP echo), Reality (204),
     Reality+Vision (204 + UDP echo; configs meow-muxcool.yml /
     meow-reality-muxcool.yml / meow-rv-muxcool.yml) all pass.
   - CI: `crates/meow-app/tests/smux_singbox_integration.rs` runs the full
     stack against the pinned sing-box (1.14.0), including `padding: true`
     smux / yamux / h2mux sessions against a VLESS inbound with
     `multiplex.padding: true` (which rejects unpadded clients).
3. Physical device: a real Xray node (example-xray-node, VLESS
   Reality+Vision, config meow-real-muxcool.yml) with `protocol: muxcool`
   passes 204 (h2 + http/1.1), and 4 consecutive connections reuse one
   physical session (the log shows a single VLESS response-header
   consumption); sing-mux against the same node fails (code=000) —
   confirming the two protocol families are mutually incompatible and must
   be chosen by server type.
