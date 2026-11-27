//! Server-side XUDP codec — the UDP subset of Xray's Mux.Cool framing,
//! as carried inside VLESS `xtls-rprx-vision` padding content.
//!
//! upstream: xray common/mux/frame.go (frame layout, meta cap),
//!           xray common/mux/server.go (server session semantics),
//!           xray common/mux/writer.go (response writer: replies are
//!             always Keep, never New),
//!           xray common/mux/reader.go (8192 payload cap),
//!           xray common/xudp/xudp.go (client write/read shapes),
//!           xray proxy/freedom/freedom.go:284-301 (reply source address
//!             rewrite: resolved IP back to the original domain);
//!           sagernet/sing-vmess mux.go / xudp.go (mihomo's mux server
//!             and XUDP client).
//!
//! # Wire format
//!
//! ```text
//! meta_len   u16 BE    length of the meta block — covers sid..meta end,
//!                       NOT itself and NOT payload_len
//! meta:
//!   session_id u16 BE
//!   status     u8      1=New 2=Keep 3=End 4=KeepAlive
//!   option     u8      bit 0x01 = Data, bit 0x02 = Error
//!   (New, and Keep frames carrying a per-packet target:)
//!     network u8       1=TCP 2=UDP
//!     port    u16 BE   port BEFORE address (VMess/VLESS layout)
//!     atype   u8       0x01 IPv4 | 0x02 domain | 0x03 IPv6
//!     address ...
//!   (UDP New only, optional:)  GlobalID 8 bytes
//! payload_len u16 BE   present iff option & Data
//! payload               payload_len bytes — one UDP datagram, never split
//! ```
//!
//! # Scope and strictness
//!
//! This is the **server** side of the UDP subset only: TCP-over-mux
//! streams are out of scope by design, and a New frame announcing the TCP
//! network is connection-fatal (the hard contract of xray's
//! vision+Mux path — `AllowedNetwork=UDP`, server.go:189-193).
//!
//! Strictness beyond xray, all deliberate and interop-safe because no
//! real client (xray v26.3.27, mihomo/sing-vmess, meow) ever emits the
//! rejected shapes:
//!
//! * unknown status / unknown option bits / Error bit outside End —
//!   xray kills the connection for unknown status already;
//! * End carrying the Data bit — it would desync the frame stream;
//! * trailing meta bytes that are not exactly the 8-byte GlobalID on a
//!   New frame, or exactly the per-packet target on a Keep frame —
//!   xray silently discards them; the spec requires recognizing the known
//!   optional trailing fields instead of treating unknown tails as valid;
//! * empty domain addresses (structurally malformed in meow's metadata
//!   model, where an empty host means "use the IP literal") and non-UTF-8
//!   domains (unrepresentable in `Metadata::host`).
//!
//! Lenient where the references are, when strictness would only widen the
//! blast radius of one junk datagram to the whole connection: port 0
//! targets parse (the per-datagram dial fails naturally), and payloads on
//! KeepAlive frames are read and discarded.
//!
//! Integration contract for the listener wave: XUDP frames ride the
//! Vision content byte stream directly, with no mux session layer in
//! between, and the connection must never switch to DIRECT — even when a
//! UDP payload happens to start with TLS-looking bytes (spec §2.3; xray
//! lacks this guarantee and can corrupt such streams).

use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicUsize, Ordering};

use bytes::{BufMut, Bytes, BytesMut};
use parking_lot::Mutex;
use smol_str::SmolStr;

use super::muxcool::{
    ATYPE_DOMAIN, ATYPE_IPV4, ATYPE_IPV6, MAX_META, MAX_UDP_PAYLOAD, NETWORK_TCP, NETWORK_UDP,
    OPTION_DATA, OPTION_ERROR, STATUS_END, STATUS_KEEP, STATUS_KEEPALIVE, STATUS_NEW,
};

/// Hard cap on the meta block — xray `FrameMetadata.Unmarshal` rejects
/// meta_len > 512 (frame.go:119-120). Valid strict XUDP frames never
/// approach it; the cap is a garbage-traffic bound.
pub const MAX_META_LEN: usize = MAX_META;

/// Hard cap on one datagram payload — xray's `PacketReader` rejects
/// `size > buf.Size` and aborts the whole mux connection
/// (common/mux/reader.go:41, common/buf/buffer.go:13). Replies larger
/// than this are dropped, never split across frames.
pub const MAX_PAYLOAD_LEN: usize = MAX_UDP_PAYLOAD;

/// Active-session cap per physical connection. The spec budget is
/// `(sid, target)` flows — enforced where the tunnel flows are created —
/// but every session carries at least one target, so capping session ids
/// at the same number keeps the table itself bounded under sid spraying.
/// Real XUDP clients only ever use sid 0.
pub const MAX_SESSIONS: usize = 128;

const XUDP_POOL_SHARDS: usize = 4;
const XUDP_POOL_SLABS_PER_SHARD: usize = 4;
const XUDP_POOL_SLAB_LEN: usize = 16 * 1024;

struct XudpSlabShard {
    slots: [Option<BytesMut>; XUDP_POOL_SLABS_PER_SHARD],
    next: usize,
}

impl XudpSlabShard {
    const fn new() -> Self {
        Self {
            slots: [const { None }; XUDP_POOL_SLABS_PER_SHARD],
            next: 0,
        }
    }

    fn checkout(&mut self, len: usize) -> Option<BytesMut> {
        for offset in 0..XUDP_POOL_SLABS_PER_SHARD {
            let index = (self.next + offset) % XUDP_POOL_SLABS_PER_SHARD;
            if self.slots[index].is_none() {
                self.slots[index] = Some(BytesMut::with_capacity(XUDP_POOL_SLAB_LEN));
            }
            let tail = self.slots[index].as_mut()?;
            debug_assert_eq!(tail.len(), 0);
            if tail.capacity() < len && !tail.try_reclaim(len) {
                continue;
            }
            let rest = tail.split_off(len);
            let out = std::mem::replace(tail, rest);
            self.next = index;
            return Some(out);
        }
        None
    }
}

static XUDP_SLAB_POOL: [Mutex<XudpSlabShard>; XUDP_POOL_SHARDS] =
    [const { Mutex::new(XudpSlabShard::new()) }; XUDP_POOL_SHARDS];
static XUDP_POOL_NEXT_SHARD: AtomicUsize = AtomicUsize::new(0);

/// Exact-size writable backing for one XUDP datagram/frame. Pool slots stay
/// zero-length tails: splitting first makes the returned prefix independently
/// owned, while frozen `Bytes` in queues pin only their own slab region. When
/// every fixed slot is pinned, exact allocation is the correct fallback —
/// backpressure and queue limits belong to the listener, not the codec.
fn xudp_frame_buffer(len: usize) -> BytesMut {
    if len <= XUDP_POOL_SLAB_LEN {
        let start = XUDP_POOL_NEXT_SHARD.fetch_add(1, Ordering::Relaxed) % XUDP_POOL_SHARDS;
        for offset in 0..XUDP_POOL_SHARDS {
            let index = (start + offset) % XUDP_POOL_SHARDS;
            if let Some(buf) = XUDP_SLAB_POOL[index].lock().checkout(len) {
                return buf;
            }
        }
    }
    BytesMut::with_capacity(len)
}

// ─── Types ──────────────────────────────────────────────────────────────────

/// Network byte of a New frame. XUDP serves UDP only; TCP is surfaced so
/// the session layer can kill the connection with the precise reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XudpNetwork {
    Tcp,
    Udp,
}

/// Address of an XUDP target or reply source. Domains keep their exact
/// wire bytes (UTF-8 validated); nothing is resolved, lowercased or
/// otherwise normalized inside the codec.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XudpAddr {
    Ipv4(Ipv4Addr),
    Ipv6(Ipv6Addr),
    Domain(SmolStr),
}

/// A UDP target — or, in reply frames, a reply source. Same wire shape:
/// port (big-endian, before the address) + atype + address.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct XudpTarget {
    pub addr: XudpAddr,
    pub port: u16,
}

impl XudpTarget {
    /// Split into the pieces `Metadata` construction needs, domain
    /// preserved: IP targets become `(Some(ip), "", port)` and domain
    /// targets `(None, domain, port)` — the same split the UoT inbound
    /// applies to `UotAddr`. Rule matching must see the original domain,
    /// so nothing resolves here; `Metadata::lower_host` normalization is
    /// the wiring's business, exactly like the UoT path.
    pub fn metadata_parts(&self) -> (Option<IpAddr>, &str, u16) {
        match &self.addr {
            XudpAddr::Ipv4(ip) => (Some(IpAddr::V4(*ip)), "", self.port),
            XudpAddr::Ipv6(ip) => (Some(IpAddr::V6(*ip)), "", self.port),
            XudpAddr::Domain(host) => (None, host.as_str(), self.port),
        }
    }
}

impl fmt::Display for XudpTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.addr {
            XudpAddr::Ipv4(ip) => write!(f, "{ip}:{}", self.port),
            XudpAddr::Ipv6(ip) => write!(f, "[{ip}]:{}", self.port),
            XudpAddr::Domain(host) => write!(f, "{host}:{}", self.port),
        }
    }
}

/// One decoded frame. Illegal shapes are unrepresentable rather than
/// validated against: Error exists only on End, payload only where the
/// Data bit allows it, and a targeted Keep is always UDP (the decoder
/// rejects any other network byte in that position).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XudpFrame {
    /// Open a session. `network` is the peer's requested network byte —
    /// UDP is the only servable one; TCP must kill the connection at the
    /// session layer. `global_id` is the exact trailing 8 bytes when
    /// present (all-zero included — xray treats zero as absent, the codec
    /// reports wire fidelity); migration across connections is
    /// deliberately not implemented, matching mihomo/sing servers.
    New {
        session_id: u16,
        network: XudpNetwork,
        target: XudpTarget,
        global_id: Option<[u8; 8]>,
        payload: Option<Bytes>,
    },
    /// Continue a session. `target` is the per-packet override when the
    /// peer attached one (network byte enforced UDP); `None` means the
    /// session's default target. A bare Keep carries no payload.
    Keep {
        session_id: u16,
        target: Option<XudpTarget>,
        payload: Option<Bytes>,
    },
    /// Tear down a session. `error` is the peer's Error bit.
    End { session_id: u16, error: bool },
    /// Heartbeat. Never answered; any payload is read and dropped by the
    /// session layer (xray `handleStatusKeepAlive` parity).
    KeepAlive {
        session_id: u16,
        payload: Option<Bytes>,
    },
}

// ─── Errors ─────────────────────────────────────────────────────────────────

/// Every violation the codec or the session machine can hit. All of them
/// are connection-fatal by contract: once one is observed the physical
/// connection is garbage (or hostile) and must be closed — there is no
/// frame-level recovery in Mux.Cool.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum XudpError {
    #[error("xudp: meta_len {0} smaller than the 4-byte fixed header")]
    MetaLenTooSmall(u16),
    #[error("xudp: meta_len {0} exceeds the 512-byte cap")]
    MetaLenTooLarge(u16),
    #[error("xudp: payload_len {0} exceeds the 8192-byte cap")]
    PayloadTooLarge(u16),
    #[error("xudp: unknown status {0:#04x}")]
    UnknownStatus(u8),
    #[error("xudp: unknown option bits {0:#04x}")]
    UnknownOptionBits(u8),
    #[error("xudp: Error bit on a {0} frame — defined only for End")]
    MisplacedErrorBit(&'static str),
    #[error("xudp: End frame carrying the Data bit desyncs the stream")]
    EndWithData,
    #[error("xudp: End/KeepAlive frame meta_len must be exactly 4, got {0}")]
    BloatedControlFrame(u16),
    #[error("xudp: New frame without room for network+address (meta_len {0})")]
    TruncatedNewTarget(u16),
    #[error("xudp: unknown network byte {0:#04x}")]
    UnknownNetwork(u8),
    #[error("xudp: TCP network on Keep frame target — XUDP serves UDP only")]
    TcpKeepTarget,
    #[error("xudp: truncated port/address block")]
    TruncatedAddress,
    #[error("xudp: unknown address type {0:#04x}")]
    UnknownAddressType(u8),
    #[error("xudp: empty domain address")]
    EmptyDomain,
    #[error("xudp: domain address is not valid UTF-8")]
    InvalidDomainUtf8,
    #[error(
        "xudp: {0} trailing meta bytes after New target — only exactly 8 (GlobalID) are defined"
    )]
    BadNewTrailing(usize),
    #[error("xudp: {0} trailing meta bytes after Keep target — none are defined")]
    BadKeepTrailing(usize),
    #[error("xudp: TCP New on a UDP-only vision mux — the connection must die")]
    TcpNewNotPermitted,
    #[error("xudp: New for already-active session id {0}")]
    DuplicateSession(u16),
    #[error("xudp: active session count exceeds {MAX_SESSIONS}")]
    SessionLimitExceeded,
    #[error("xudp: UDP is not permitted on this inbound")]
    UdpNotPermitted,
}

// ─── Meta parsing (pure) ────────────────────────────────────────────────────

/// Parsed meta block before the payload is known. Internal — the public
/// frame type is assembled only once the payload is complete, so no
/// consumer ever sees a half-built frame.
#[derive(Debug)]
struct FrameHead {
    session_id: u16,
    status: u8,
    error_bit: bool,
    network: Option<XudpNetwork>,
    target: Option<XudpTarget>,
    global_id: Option<[u8; 8]>,
    has_data: bool,
}

/// Parse `[port u16be][atype][address]` with exact consumption tracking.
/// Returns the target and the number of input bytes consumed — the
/// caller strict-checks the trailing remainder.
fn parse_addr_port(b: &[u8]) -> Result<(XudpTarget, usize), XudpError> {
    if b.len() < 3 {
        return Err(XudpError::TruncatedAddress);
    }
    let port = u16::from_be_bytes([b[0], b[1]]);
    match b[2] {
        ATYPE_IPV4 => {
            if b.len() < 7 {
                return Err(XudpError::TruncatedAddress);
            }
            Ok((
                XudpTarget {
                    addr: XudpAddr::Ipv4(Ipv4Addr::new(b[3], b[4], b[5], b[6])),
                    port,
                },
                7,
            ))
        }
        ATYPE_IPV6 => {
            if b.len() < 19 {
                return Err(XudpError::TruncatedAddress);
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&b[3..19]);
            Ok((
                XudpTarget {
                    addr: XudpAddr::Ipv6(Ipv6Addr::from(octets)),
                    port,
                },
                19,
            ))
        }
        ATYPE_DOMAIN => {
            if b.len() < 4 {
                return Err(XudpError::TruncatedAddress);
            }
            let len = b[3] as usize;
            if len == 0 {
                return Err(XudpError::EmptyDomain);
            }
            if b.len() < 4 + len {
                return Err(XudpError::TruncatedAddress);
            }
            let bytes = &b[4..4 + len];
            let Ok(domain) = std::str::from_utf8(bytes) else {
                return Err(XudpError::InvalidDomainUtf8);
            };
            Ok((
                XudpTarget {
                    addr: XudpAddr::Domain(SmolStr::new(domain)),
                    port,
                },
                4 + len,
            ))
        }
        other => Err(XudpError::UnknownAddressType(other)),
    }
}

/// Parse a complete meta block. `meta` is exactly `meta_len` bytes, the
/// length itself already cap-checked by the decoder.
fn parse_frame_meta(meta: &[u8]) -> Result<FrameHead, XudpError> {
    debug_assert!(meta.len() >= 4, "meta_len < 4 rejected before scratch fill");
    let session_id = u16::from_be_bytes([meta[0], meta[1]]);
    let status = meta[2];
    let option = meta[3];

    if !matches!(
        status,
        STATUS_NEW | STATUS_KEEP | STATUS_END | STATUS_KEEPALIVE
    ) {
        return Err(XudpError::UnknownStatus(status));
    }
    if option & !(OPTION_DATA | OPTION_ERROR) != 0 {
        return Err(XudpError::UnknownOptionBits(option));
    }
    let has_data = option & OPTION_DATA != 0;
    let error_bit = option & OPTION_ERROR != 0;

    let rest = &meta[4..];
    match status {
        STATUS_NEW => {
            if error_bit {
                return Err(XudpError::MisplacedErrorBit("New"));
            }
            // network byte + minimum port/atype/IPv4 address = 1+2+1+4.
            if rest.len() < 8 {
                return Err(XudpError::TruncatedNewTarget(meta.len() as u16));
            }
            let network = match rest[0] {
                NETWORK_TCP => XudpNetwork::Tcp,
                NETWORK_UDP => XudpNetwork::Udp,
                other => return Err(XudpError::UnknownNetwork(other)),
            };
            let (target, consumed) = parse_addr_port(&rest[1..])?;
            let trailing = &rest[1 + consumed..];
            let global_id = match trailing.len() {
                0 => None,
                8 => {
                    let mut id = [0u8; 8];
                    id.copy_from_slice(trailing);
                    Some(id)
                }
                n => return Err(XudpError::BadNewTrailing(n)),
            };
            Ok(FrameHead {
                session_id,
                status,
                error_bit: false,
                network: Some(network),
                target: Some(target),
                global_id,
                has_data,
            })
        }
        STATUS_KEEP => {
            if error_bit {
                return Err(XudpError::MisplacedErrorBit("Keep"));
            }
            let (network, target) = if rest.is_empty() {
                (None, None)
            } else {
                // xray parses a Keep target only when byte4 == UDP; this
                // server is UDP-only, so anything else in that position —
                // TCP included — is a protocol violation, not a hint to
                // ignore the bytes.
                match rest[0] {
                    NETWORK_UDP => {}
                    NETWORK_TCP => return Err(XudpError::TcpKeepTarget),
                    other => return Err(XudpError::UnknownNetwork(other)),
                }
                let (target, consumed) = parse_addr_port(&rest[1..])?;
                let trailing = &rest[1 + consumed..];
                if !trailing.is_empty() {
                    return Err(XudpError::BadKeepTrailing(trailing.len()));
                }
                (Some(XudpNetwork::Udp), Some(target))
            };
            Ok(FrameHead {
                session_id,
                status,
                error_bit: false,
                network,
                target,
                global_id: None,
                has_data,
            })
        }
        STATUS_END => {
            if has_data {
                return Err(XudpError::EndWithData);
            }
            if !rest.is_empty() {
                return Err(XudpError::BloatedControlFrame(meta.len() as u16));
            }
            Ok(FrameHead {
                session_id,
                status,
                error_bit,
                network: None,
                target: None,
                global_id: None,
                has_data: false,
            })
        }
        STATUS_KEEPALIVE => {
            if error_bit {
                return Err(XudpError::MisplacedErrorBit("KeepAlive"));
            }
            if !rest.is_empty() {
                return Err(XudpError::BloatedControlFrame(meta.len() as u16));
            }
            Ok(FrameHead {
                session_id,
                status,
                error_bit: false,
                network: None,
                target: None,
                global_id: None,
                has_data,
            })
        }
        _ => unreachable!("status validated above"),
    }
}

// ─── Incremental decoder ────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DecodeState {
    /// Filling the 2-byte meta_len.
    MetaLen,
    /// Filling the meta scratch.
    Meta,
    /// Filling the 2-byte payload_len (only when the Data bit is set).
    PayloadLen,
    /// Filling the payload buffer.
    Payload,
}

/// Incremental XUDP frame decoder for one physical connection.
///
/// Feed bytes in any fragmentation — frame boundaries are recovered purely
/// from the length fields. Completed frames queue internally and drain
/// through [`XudpDecoder::next_frame`]. All peer-controlled lengths are
/// validated against the hard caps before any payload memory is committed:
/// the meta block accumulates in a fixed 512-byte scratch, and the payload
/// buffer is sized only after payload_len passes the 8192 cap.
///
/// Every error is terminal: the frame stream can no longer be trusted and
/// the physical connection must close. Mid-frame EOF is the wiring's
/// concern — a half-arrived datagram is simply never emitted.
pub struct XudpDecoder {
    state: DecodeState,
    len_scratch: [u8; 2],
    len_pos: usize,
    meta_len: usize,
    meta_scratch: [u8; MAX_META_LEN],
    meta_pos: usize,
    head: Option<FrameHead>,
    payload_len: usize,
    payload: Option<BytesMut>,
    ready: VecDeque<XudpFrame>,
}

impl Default for XudpDecoder {
    fn default() -> Self {
        Self::new()
    }
}

impl XudpDecoder {
    pub fn new() -> Self {
        Self {
            state: DecodeState::MetaLen,
            len_scratch: [0; 2],
            len_pos: 0,
            meta_len: 0,
            meta_scratch: [0; MAX_META_LEN],
            meta_pos: 0,
            head: None,
            payload_len: 0,
            payload: None,
            ready: VecDeque::new(),
        }
    }

    /// Oldest completed frame, if any.
    pub fn next_frame(&mut self) -> Option<XudpFrame> {
        self.ready.pop_front()
    }

    /// True when EOF would land inside a frame — the wiring uses this to
    /// log a truncation rather than a clean close. A half-arrived
    /// datagram is never emitted either way.
    pub fn mid_frame(&self) -> bool {
        self.state != DecodeState::MetaLen || self.len_pos != 0
    }

    /// Feed bytes fragmented arbitrarily. Consumes the whole input; on
    /// error the decoder is dead — frames already queued before the error
    /// point remain valid and should be drained before the connection
    /// closes.
    pub fn feed(&mut self, mut input: &[u8]) -> Result<(), XudpError> {
        while !input.is_empty() {
            match self.state {
                DecodeState::MetaLen | DecodeState::PayloadLen => {
                    let need = 2 - self.len_pos;
                    let take = need.min(input.len());
                    self.len_scratch[self.len_pos..self.len_pos + take]
                        .copy_from_slice(&input[..take]);
                    self.len_pos += take;
                    input = &input[take..];
                    if self.len_pos < 2 {
                        continue;
                    }
                    self.len_pos = 0;
                    let len = u16::from_be_bytes(self.len_scratch) as usize;
                    match self.state {
                        DecodeState::MetaLen => {
                            if len < 4 {
                                return Err(XudpError::MetaLenTooSmall(len as u16));
                            }
                            if len > MAX_META_LEN {
                                return Err(XudpError::MetaLenTooLarge(len as u16));
                            }
                            self.meta_len = len;
                            self.meta_pos = 0;
                            self.state = DecodeState::Meta;
                        }
                        DecodeState::PayloadLen => {
                            if len > MAX_PAYLOAD_LEN {
                                return Err(XudpError::PayloadTooLarge(len as u16));
                            }
                            self.payload_len = len;
                            self.payload = (len != 0).then(|| xudp_frame_buffer(len));
                            if len == 0 {
                                self.emit_frame();
                                self.state = DecodeState::MetaLen;
                            } else {
                                self.state = DecodeState::Payload;
                            }
                        }
                        _ => unreachable!(),
                    }
                }
                DecodeState::Meta => {
                    let need = self.meta_len - self.meta_pos;
                    let take = need.min(input.len());
                    self.meta_scratch[self.meta_pos..self.meta_pos + take]
                        .copy_from_slice(&input[..take]);
                    self.meta_pos += take;
                    input = &input[take..];
                    if self.meta_pos < self.meta_len {
                        continue;
                    }
                    let head = parse_frame_meta(&self.meta_scratch[..self.meta_len])?;
                    let has_data = head.has_data;
                    self.head = Some(head);
                    self.state = if has_data {
                        DecodeState::PayloadLen
                    } else {
                        self.emit_frame();
                        DecodeState::MetaLen
                    };
                }
                DecodeState::Payload => {
                    let payload = self
                        .payload
                        .as_mut()
                        .expect("non-zero payload length allocates its gather buffer");
                    let need = self.payload_len - payload.len();
                    let take = need.min(input.len());
                    payload.extend_from_slice(&input[..take]);
                    input = &input[take..];
                    if payload.len() < self.payload_len {
                        continue;
                    }
                    self.emit_frame();
                    self.state = DecodeState::MetaLen;
                }
            }
        }
        Ok(())
    }

    /// Assemble the public frame from the parsed head plus whatever payload
    /// accumulated, and queue it. Freezing moves backing ownership to the
    /// queued datagram; no decoder-owned copy remains to pin the slab.
    fn emit_frame(&mut self) {
        let head = self.head.take().expect("emit requires a parsed head");
        let payload = head.has_data.then(|| {
            self.payload.take().map_or_else(Bytes::new, |buf| {
                debug_assert_eq!(buf.len(), self.payload_len);
                buf.freeze()
            })
        });
        let frame = match head.status {
            STATUS_NEW => XudpFrame::New {
                session_id: head.session_id,
                network: head.network.expect("New always carries network"),
                target: head.target.expect("New always carries a target"),
                global_id: head.global_id,
                payload,
            },
            STATUS_KEEP => XudpFrame::Keep {
                session_id: head.session_id,
                target: head.target,
                payload,
            },
            STATUS_END => XudpFrame::End {
                session_id: head.session_id,
                error: head.error_bit,
            },
            STATUS_KEEPALIVE => XudpFrame::KeepAlive {
                session_id: head.session_id,
                payload,
            },
            _ => unreachable!("status validated at parse time"),
        };
        self.ready.push_back(frame);
    }
}

// ─── Reply encoding ─────────────────────────────────────────────────────────

/// Append `[network][port u16be][atype][address]` for a UDP target/source.
/// Returns `None` when the domain exceeds the one-byte length prefix or is
/// empty — shapes the decoder would reject, so encoder output is always
/// decodable.
fn put_udp_target(out: &mut BytesMut, target: &XudpTarget) -> Option<()> {
    out.put_u8(NETWORK_UDP);
    out.put_u16(target.port);
    match &target.addr {
        XudpAddr::Ipv4(ip) => {
            out.put_u8(ATYPE_IPV4);
            out.put_slice(&ip.octets());
        }
        XudpAddr::Ipv6(ip) => {
            out.put_u8(ATYPE_IPV6);
            out.put_slice(&ip.octets());
        }
        XudpAddr::Domain(host) => {
            let bytes = host.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return None;
            }
            out.put_u8(ATYPE_DOMAIN);
            out.put_u8(bytes.len() as u8);
            out.put_slice(bytes);
        }
    }
    Some(())
}

/// Wire length of the `[network][port][atype][address]` block, or `None`
/// for a source the one-byte domain length cannot represent.
fn udp_target_wire_len(target: &XudpTarget) -> Option<usize> {
    match &target.addr {
        XudpAddr::Ipv4(_) => Some(1 + 2 + 1 + 4),
        XudpAddr::Ipv6(_) => Some(1 + 2 + 1 + 16),
        XudpAddr::Domain(host) => {
            let len = host.len();
            (1..=u8::MAX as usize)
                .contains(&len)
                .then_some(1 + 2 + 1 + 1 + len)
        }
    }
}

/// Exact encoded length of [`encode_reply_keep_data`], with the same
/// validity verdict but none of the allocation or copying. The wiring uses
/// this to reserve queue budget before paying for the frame.
pub fn encoded_reply_keep_data_len(
    source: Option<&XudpTarget>,
    payload_len: usize,
) -> Option<usize> {
    if payload_len > MAX_PAYLOAD_LEN {
        return None;
    }
    let target_len = source.map_or(Some(0), udp_target_wire_len)?;
    // meta_len field + fixed meta + optional source + payload_len + payload.
    Some(2 + 4 + target_len + 2 + payload_len)
}

/// Encode a reply frame: Keep+Data on the session the client opened —
/// the server never sends New (xray `NewResponseWriter` is born with
/// `followup=true`). `source` is the reply's real source address as the
/// tunnel observed it; supplying it matters on sessions whose per-packet
/// targets change, where a bare reply is ambiguous to the client. `None`
/// encodes the bare meta_len=4 form, which clients read as "from the
/// session default target".
///
/// Returns `None` — the wiring drops and counts the datagram, per spec —
/// when the payload exceeds the 8192 cap or the source address cannot be
/// represented. Oversize datagrams are never split across frames.
pub fn encode_reply_keep_data(
    session_id: u16,
    source: Option<&XudpTarget>,
    payload: &[u8],
) -> Option<Bytes> {
    let capacity = encoded_reply_keep_data_len(source, payload.len())?;
    let mut out = xudp_frame_buffer(capacity);
    out.put_u16(0); // meta_len placeholder, patched below
    out.put_u16(session_id);
    out.put_u8(STATUS_KEEP);
    out.put_u8(OPTION_DATA);
    if let Some(source) = source {
        put_udp_target(&mut out, source)?;
    }
    let meta_len = out.len() - 2;
    out[0..2].copy_from_slice(&(meta_len as u16).to_be_bytes());
    out.put_u16(payload.len() as u16);
    out.put_slice(payload);
    Some(out.freeze())
}

/// Encode an End frame — how the server tears a session down: after the
/// tunnel flow dies, or answering data the client sent for a session this
/// side never opened (xray `handleStatusKeep`'s unknown-sid path).
pub fn encode_end(session_id: u16, error: bool) -> Bytes {
    let mut out = BytesMut::with_capacity(6);
    out.put_u16(4);
    out.put_u16(session_id);
    out.put_u8(STATUS_END);
    out.put_u8(if error { OPTION_ERROR } else { 0 });
    out.freeze()
}

/// Pick the wire source address for a reply datagram — xray freedom's
/// rule (freedom.go:284-301): when the flow's target was a domain and the
/// reply arrives from the IP the dial actually used, the source is
/// rewritten to the original domain so domain semantics survive the
/// round trip. The port always comes from the real reply. When the target
/// was an IP literal, or the dialed IP is unknown (a proxied outbound
/// resolves remotely and never reports it), or the reply came from
/// somewhere else entirely, the real source goes on the wire unchanged.
pub fn reply_source(
    target: &XudpTarget,
    dialed_ip: Option<IpAddr>,
    actual_source: SocketAddr,
) -> XudpTarget {
    let ip_addr = match actual_source.ip() {
        IpAddr::V4(v4) => XudpAddr::Ipv4(v4),
        IpAddr::V6(v6) => XudpAddr::Ipv6(v6),
    };
    match (&target.addr, dialed_ip) {
        (XudpAddr::Domain(_), Some(dialed)) if dialed == actual_source.ip() => XudpTarget {
            addr: target.addr.clone(),
            port: actual_source.port(),
        },
        _ => XudpTarget {
            addr: ip_addr,
            port: actual_source.port(),
        },
    }
}

// ─── Server session machine ─────────────────────────────────────────────────

/// What the session machine wants the wiring to do next. One input frame
/// produces at most one action; datagram delivery always carries the
/// effective target with the domain preserved, ready for `Metadata`
/// construction and tunnel routing — never a pre-resolved or normalized
/// form.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum XudpAction {
    /// A New frame opened a session. `target` is its default target —
    /// always UDP, since TCP New is fatal before an action exists.
    /// `first_datagram` is the New frame's own payload when it carried
    /// one (xray clients send New+Data; meow's client sends a bare New
    /// and follows with Keep+Data). The datagram belongs to the default
    /// target.
    NewSession {
        session_id: u16,
        target: XudpTarget,
        global_id: Option<[u8; 8]>,
        first_datagram: Option<Bytes>,
    },
    /// A datagram for an open session. `target` is the effective
    /// per-packet target: the frame's explicit override when present —
    /// which affects this packet only — else the session default.
    Datagram {
        session_id: u16,
        target: XudpTarget,
        payload: Bytes,
    },
    /// The peer ended the session; tear the tunnel flow down.
    /// `remote_error` is the peer's Error bit.
    SessionEnd { session_id: u16, remote_error: bool },
    /// Data arrived for a session this side has no record of — late
    /// traffic for an ended session, or garbage. xray's answer is an End
    /// frame for that session id with the datagram dropped
    /// (server.go:305-312): encode `encode_end(session_id, false)` onto
    /// the connection and move on. Not connection-fatal — racing Ends are
    /// ordinary UDP life.
    ReplyEnd { session_id: u16 },
}

struct SessionState {
    default_target: XudpTarget,
}

/// Server-side XUDP session state machine for one physical connection.
///
/// Pure and synchronous: decoded frames go in, actions come out; all I/O,
/// tunnel routing, flow bookkeeping and queue budgets belong to the
/// wiring layer. Session ids are never validated against 0 — xray clients
/// only use sid 0, but generic Mux.Cool clients allocate freely and both
/// shapes are legal.
pub struct XudpServer {
    udp_permitted: bool,
    sessions: HashMap<u16, SessionState>,
}

impl XudpServer {
    /// `udp_permitted` is the `udp: false` judgement primitive: with the
    /// listener configured to refuse UDP, every frame — whatever its
    /// shape — is connection-fatal. The primary enforcement point is the
    /// VLESS request layer (a `udp: false` inbound rejects command 0x03
    /// before any XUDP byte arrives); this is the codec-level backstop.
    pub fn new(udp_permitted: bool) -> Self {
        Self {
            udp_permitted,
            sessions: HashMap::new(),
        }
    }

    pub fn active_session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Whether a session id is currently open — exposed for wiring-side
    /// flow bookkeeping.
    pub fn has_session(&self, session_id: u16) -> bool {
        self.sessions.contains_key(&session_id)
    }

    /// The session's default target, for wiring that keys flows by it.
    pub fn default_target(&self, session_id: u16) -> Option<&XudpTarget> {
        self.sessions.get(&session_id).map(|s| &s.default_target)
    }

    /// Consume one decoded frame. Errors are connection-fatal.
    pub fn handle_frame(&mut self, frame: XudpFrame) -> Result<Option<XudpAction>, XudpError> {
        if !self.udp_permitted {
            return Err(XudpError::UdpNotPermitted);
        }
        match frame {
            XudpFrame::New {
                session_id,
                network,
                target,
                global_id,
                payload,
            } => {
                // xray: vision+Mux sets AllowedNetwork=UDP and a TCP New
                // breaks the whole Mux connection (server.go:189-193) —
                // the spec's hard contract.
                if network == XudpNetwork::Tcp {
                    return Err(XudpError::TcpNewNotPermitted);
                }
                if self.sessions.contains_key(&session_id) {
                    return Err(XudpError::DuplicateSession(session_id));
                }
                if self.sessions.len() >= MAX_SESSIONS {
                    return Err(XudpError::SessionLimitExceeded);
                }
                self.sessions.insert(
                    session_id,
                    SessionState {
                        default_target: target.clone(),
                    },
                );
                Ok(Some(XudpAction::NewSession {
                    session_id,
                    target,
                    global_id,
                    first_datagram: payload,
                }))
            }
            XudpFrame::Keep {
                session_id,
                target,
                payload,
            } => {
                // xray checks the Data bit before the session lookup: a
                // dataless Keep is a no-op even for unknown sessions.
                let Some(payload) = payload else {
                    return Ok(None);
                };
                let Some(session) = self.sessions.get(&session_id) else {
                    return Ok(Some(XudpAction::ReplyEnd { session_id }));
                };
                let target = target.unwrap_or_else(|| session.default_target.clone());
                Ok(Some(XudpAction::Datagram {
                    session_id,
                    target,
                    payload,
                }))
            }
            XudpFrame::End { session_id, error } => {
                // End for a session this side never opened is silent —
                // racing teardown is ordinary.
                if self.sessions.remove(&session_id).is_some() {
                    Ok(Some(XudpAction::SessionEnd {
                        session_id,
                        remote_error: error,
                    }))
                } else {
                    Ok(None)
                }
            }
            // Legal KeepAlive is never answered; a payload it carries is
            // read and dropped (xray handleStatusKeepAlive parity).
            XudpFrame::KeepAlive { .. } => Ok(None),
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    mod vectors {
        pub(crate) const XUDP_NEW_DATA: &str = include_str!("testdata/05_xudp_new_data.hexstr");
        pub(crate) const XUDP_KEEP_END: &str = include_str!("testdata/06_xudp_keep_end.hexstr");
        pub(crate) const XUDP_REPLY_KEEP_DATA: &str =
            include_str!("testdata/07_xudp_reply_keep_data.hexstr");

        pub(crate) fn decode(hex: &str) -> Vec<u8> {
            let hex = hex.trim();
            assert_eq!(hex.len() % 2, 0, "golden hex must be byte-aligned");
            (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).expect("golden hex is valid"))
                .collect()
        }
    }

    fn decode_all(bytes: &[u8]) -> Vec<XudpFrame> {
        let mut decoder = XudpDecoder::new();
        decoder.feed(bytes).expect("feed must succeed");
        let mut frames = Vec::new();
        while let Some(frame) = decoder.next_frame() {
            frames.push(frame);
        }
        frames
    }

    fn ipv4_target(a: u8, b: u8, c: u8, d: u8, port: u16) -> XudpTarget {
        XudpTarget {
            addr: XudpAddr::Ipv4(Ipv4Addr::new(a, b, c, d)),
            port,
        }
    }

    fn domain_target(host: &str, port: u16) -> XudpTarget {
        XudpTarget {
            addr: XudpAddr::Domain(SmolStr::new(host)),
            port,
        }
    }

    /// Hand-encode client-style frames for session-machine tests, mirroring
    /// the xray/mihomo client write paths byte for byte.
    mod client_encode {
        use bytes::{BufMut, BytesMut};

        pub(super) fn frame(
            sid: u16,
            status: u8,
            option: u8,
            extra_meta: &[u8],
            payload: Option<&[u8]>,
        ) -> Vec<u8> {
            let mut meta = BytesMut::new();
            meta.put_u16(sid);
            meta.put_u8(status);
            meta.put_u8(option);
            meta.put_slice(extra_meta);
            let mut out = BytesMut::new();
            out.put_u16(meta.len() as u16);
            out.put_slice(&meta);
            if let Some(data) = payload {
                out.put_u16(data.len() as u16);
                out.put_slice(data);
            }
            out.to_vec()
        }

        pub(super) fn udp_target_meta(port: u16, atype: u8, addr: &[u8]) -> Vec<u8> {
            let mut meta = vec![0x02]; // network UDP
            meta.extend_from_slice(&port.to_be_bytes());
            meta.push(atype);
            meta.extend_from_slice(addr);
            meta
        }

        pub(super) fn new_udp_data(
            sid: u16,
            target_meta: &[u8],
            global_id: Option<&[u8; 8]>,
            payload: &[u8],
        ) -> Vec<u8> {
            let mut extra = target_meta.to_vec();
            if let Some(gid) = global_id {
                extra.extend_from_slice(gid);
            }
            frame(sid, 0x01, 0x01, &extra, Some(payload))
        }

        pub(super) fn keep_data(sid: u16, target_meta: Option<&[u8]>, payload: &[u8]) -> Vec<u8> {
            frame(sid, 0x02, 0x01, target_meta.unwrap_or(&[]), Some(payload))
        }

        pub(super) fn end(sid: u16, error: bool) -> Vec<u8> {
            frame(sid, 0x03, if error { 0x02 } else { 0 }, &[], None)
        }
    }

    // ─── Golden vector 05: XUDP New+Data byte-exact decode ──────────────

    #[test]
    fn golden_05_new_data_decodes_byte_exactly() {
        let bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        let frames = decode_all(&bytes);
        assert_eq!(frames.len(), 1);
        let XudpFrame::New {
            session_id,
            network,
            target,
            global_id,
            payload,
        } = &frames[0]
        else {
            panic!("golden 05 must be a New frame: {:?}", frames[0]);
        };
        assert_eq!(*session_id, 0);
        assert_eq!(*network, XudpNetwork::Udp);
        assert_eq!(*target, ipv4_target(93, 184, 216, 34, 53));
        assert_eq!(*global_id, Some([1, 2, 3, 4, 5, 6, 7, 8]));
        assert_eq!(payload.as_deref(), Some(b"hello-udp-payload-1".as_slice()));
    }

    #[test]
    fn golden_05_frame_layout_offsets() {
        // meta_len covers sid..meta end but not itself nor payload_len:
        // 2+1+1+1+2+1+4+8 = 20, then payload_len u16 + 19 payload bytes.
        let bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        assert_eq!(u16::from_be_bytes([bytes[0], bytes[1]]), 20);
        assert_eq!(bytes.len(), 2 + 20 + 2 + 19);
    }

    // ─── Golden vector 06: Keep targeted / Keep bare / End ──────────────

    #[test]
    fn golden_06_three_frames_decode_in_order() {
        let bytes = vectors::decode(vectors::XUDP_KEEP_END);
        let frames = decode_all(&bytes);
        assert_eq!(
            frames.len(),
            3,
            "packet boundaries must survive in a byte stream"
        );

        let XudpFrame::Keep {
            session_id,
            target,
            payload,
        } = &frames[0]
        else {
            panic!("frame 1 must be Keep: {:?}", frames[0]);
        };
        assert_eq!(*session_id, 0);
        assert_eq!(
            target.as_ref().unwrap(),
            &domain_target("dns.example.com", 853)
        );
        assert_eq!(payload.as_deref(), Some(b"second-datagram".as_slice()));

        let XudpFrame::Keep {
            session_id,
            target,
            payload,
        } = &frames[1]
        else {
            panic!("frame 2 must be Keep: {:?}", frames[1]);
        };
        assert_eq!(*session_id, 0);
        assert_eq!(*target, None, "bare Keep carries no target");
        assert_eq!(payload.as_deref(), Some(b"third".as_slice()));

        assert_eq!(
            frames[2],
            XudpFrame::End {
                session_id: 0,
                error: false
            }
        );
    }

    // ─── Golden vector 07: reply encoding byte-exact ────────────────────

    #[test]
    fn golden_07_reply_with_domain_source_encodes_byte_exactly() {
        let bytes = vectors::decode(vectors::XUDP_REPLY_KEEP_DATA);
        // The vector is two concatenated frames: addressed reply + bare reply.
        let payload = b"reply-bytes";
        let source = domain_target("dns.example.com", 853);
        let addressed = encode_reply_keep_data(0, Some(&source), payload).unwrap();
        let bare = encode_reply_keep_data(0, None, payload).unwrap();
        let mut expected = addressed.to_vec();
        expected.extend_from_slice(&bare);
        assert_eq!(
            expected, bytes,
            "encoder must reproduce the golden bytes exactly"
        );
    }

    #[test]
    fn golden_07_replies_decode_back() {
        // Replies the server writes must parse as valid frames — the
        // decoder accepts the union of both directions' shapes.
        let bytes = vectors::decode(vectors::XUDP_REPLY_KEEP_DATA);
        let frames = decode_all(&bytes);
        assert_eq!(frames.len(), 2);
        let XudpFrame::Keep {
            target, payload, ..
        } = &frames[0]
        else {
            panic!("frame 1 must be Keep: {:?}", frames[0]);
        };
        assert_eq!(
            target.as_ref().unwrap(),
            &domain_target("dns.example.com", 853)
        );
        assert_eq!(payload.as_deref(), Some(b"reply-bytes".as_slice()));
        let XudpFrame::Keep { target, .. } = &frames[1] else {
            panic!("frame 2 must be Keep: {:?}", frames[1]);
        };
        assert_eq!(*target, None);
    }

    // ─── Fragmentation: byte-by-byte feeding equals one-shot ────────────

    #[test]
    fn byte_by_byte_feeding_matches_one_shot() {
        for vector in [vectors::XUDP_NEW_DATA, vectors::XUDP_KEEP_END] {
            let bytes = vectors::decode(vector);
            let reference = decode_all(&bytes);

            let mut decoder = XudpDecoder::new();
            for &byte in &bytes {
                decoder.feed(&[byte]).expect("byte feed must succeed");
            }
            let mut frames = Vec::new();
            while let Some(frame) = decoder.next_frame() {
                frames.push(frame);
            }
            assert_eq!(
                frames, reference,
                "fragmented feeding must not change frames"
            );
        }
    }

    #[test]
    fn truncated_mid_payload_emits_nothing_until_complete() {
        let bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        let split = bytes.len() - 5; // inside the payload
        let mut decoder = XudpDecoder::new();
        decoder.feed(&bytes[..split]).unwrap();
        assert!(
            decoder.next_frame().is_none(),
            "incomplete datagram must not be emitted"
        );
        decoder.feed(&bytes[split..]).unwrap();
        assert!(decoder.next_frame().is_some());
    }

    #[test]
    fn concatenated_goldens_decode_as_a_stream() {
        let mut bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        bytes.extend_from_slice(&vectors::decode(vectors::XUDP_KEEP_END));
        let frames = decode_all(&bytes);
        assert_eq!(frames.len(), 4, "New + Keep + Keep + End");
    }

    // ─── Decoder strictness: length caps ────────────────────────────────

    fn feed_err(bytes: &[u8]) -> XudpError {
        let mut decoder = XudpDecoder::new();
        decoder.feed(bytes).expect_err("feed must fail")
    }

    #[test]
    fn meta_len_over_512_is_rejected_before_allocation() {
        // 0x0201 = 513: the cap fires at the length field itself.
        assert_eq!(feed_err(&[0x02, 0x01]), XudpError::MetaLenTooLarge(513));
        // 512 exactly passes the cap — the bytes then fail strict parsing,
        // proving the boundary is inclusive.
        let mut junk = vec![0x02, 0x00];
        junk.extend_from_slice(&[0u8; 512]);
        let err = feed_err(&junk);
        assert!(
            !matches!(err, XudpError::MetaLenTooLarge(_)),
            "512 must pass the cap: {err}"
        );
    }

    #[test]
    fn meta_len_below_4_is_rejected() {
        assert_eq!(
            feed_err(&[0x00, 0x03, 0, 0, 0]),
            XudpError::MetaLenTooSmall(3)
        );
        assert_eq!(feed_err(&[0x00, 0x00]), XudpError::MetaLenTooSmall(0));
    }

    #[test]
    fn payload_len_over_8192_is_rejected() {
        // Valid bare Keep+Data meta, then an oversized payload length.
        let mut bytes = client_encode::frame(0, 0x02, 0x01, &[], None);
        bytes.extend_from_slice(&8193u16.to_be_bytes());
        assert_eq!(feed_err(&bytes), XudpError::PayloadTooLarge(8193));

        // 8192 exactly is the inclusive boundary — accepted.
        let payload = vec![0u8; 8192];
        let bytes = client_encode::keep_data(0, None, &payload);
        let frames = decode_all(&bytes);
        assert_eq!(frames.len(), 1);
    }

    // ─── Decoder strictness: shape violations ───────────────────────────

    #[test]
    fn unknown_status_is_rejected() {
        let bytes = client_encode::frame(0, 0x05, 0x00, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::UnknownStatus(0x05));
        let bytes = client_encode::frame(0, 0x00, 0x00, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::UnknownStatus(0x00));
    }

    #[test]
    fn unknown_option_bits_are_rejected() {
        let bytes = client_encode::frame(0, 0x02, 0x04, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::UnknownOptionBits(0x04));
        let bytes = client_encode::frame(0, 0x02, 0x83, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::UnknownOptionBits(0x83));
    }

    #[test]
    fn error_bit_outside_end_is_rejected() {
        // Keep + Error
        let target = client_encode::udp_target_meta(53, 0x01, &[1, 1, 1, 1]);
        let bytes = client_encode::frame(0, 0x02, 0x02, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::MisplacedErrorBit("Keep"));
        // New + Error
        let bytes = client_encode::frame(0, 0x01, 0x02, &target, None);
        assert_eq!(feed_err(&bytes), XudpError::MisplacedErrorBit("New"));
        // KeepAlive + Error
        let bytes = client_encode::frame(0, 0x04, 0x02, &[], None);
        assert_eq!(feed_err(&bytes), XudpError::MisplacedErrorBit("KeepAlive"));
        // End + Error is the one legal position.
        let frames = decode_all(&client_encode::end(7, true));
        assert_eq!(
            frames,
            [XudpFrame::End {
                session_id: 7,
                error: true
            }]
        );
    }

    #[test]
    fn end_with_data_bit_is_rejected() {
        let bytes = client_encode::frame(0, 0x03, 0x01, &[], Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::EndWithData);
    }

    #[test]
    fn control_frames_with_extra_meta_are_rejected() {
        // End with trailing meta bytes.
        let bytes = client_encode::frame(0, 0x03, 0x00, &[0xff], None);
        assert_eq!(feed_err(&bytes), XudpError::BloatedControlFrame(5));
        // KeepAlive ditto.
        let bytes = client_encode::frame(0, 0x04, 0x00, &[0xff, 0xff], None);
        assert_eq!(feed_err(&bytes), XudpError::BloatedControlFrame(6));
    }

    #[test]
    fn new_frame_strictness() {
        let target = client_encode::udp_target_meta(53, 0x01, &[8, 8, 8, 8]);

        // Trailing bytes other than exactly 8 (GlobalID) are rejected.
        let mut extra = target.clone();
        extra.extend_from_slice(&[0u8; 7]);
        let bytes = client_encode::frame(0, 0x01, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::BadNewTrailing(7));
        let mut extra = target.clone();
        extra.extend_from_slice(&[0u8; 9]);
        let bytes = client_encode::frame(0, 0x01, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::BadNewTrailing(9));

        // Unknown network byte.
        let mut bad_net = vec![0x03u8];
        bad_net.extend_from_slice(&target[1..]);
        let bytes = client_encode::frame(0, 0x01, 0x01, &bad_net, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::UnknownNetwork(0x03));

        // New without room for the target.
        let bytes = client_encode::frame(0, 0x01, 0x01, &[0x02, 0x00], Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::TruncatedNewTarget(6));

        // TCP network parses fine — the session layer owns the kill.
        let mut tcp = vec![0x01u8];
        tcp.extend_from_slice(&target[1..]);
        let bytes = client_encode::frame(0, 0x01, 0x01, &tcp, Some(b"x"));
        let frames = decode_all(&bytes);
        let XudpFrame::New { network, .. } = &frames[0] else {
            panic!("must be New");
        };
        assert_eq!(*network, XudpNetwork::Tcp);
    }

    #[test]
    fn keep_frame_strictness() {
        // TCP network byte in target position is a violation, not silently ignored.
        let mut extra = vec![0x01u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x01);
        extra.extend_from_slice(&[1, 1, 1, 1]);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::TcpKeepTarget);

        // Garbage network byte.
        let mut extra = vec![0x07u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x01);
        extra.extend_from_slice(&[1, 1, 1, 1]);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::UnknownNetwork(0x07));

        // Trailing bytes after a valid Keep target.
        let mut extra = client_encode::udp_target_meta(53, 0x01, &[1, 1, 1, 1]);
        extra.push(0x00);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::BadKeepTrailing(1));
    }

    #[test]
    fn address_strictness() {
        // Unknown atype.
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x09);
        extra.extend_from_slice(&[1, 2, 3, 4]);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::UnknownAddressType(0x09));

        // Truncated IPv4.
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x01);
        extra.extend_from_slice(&[1, 2, 3]);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::TruncatedAddress);

        // Empty domain.
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x02);
        extra.push(0x00);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::EmptyDomain);

        // Truncated domain.
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x02);
        extra.push(10);
        extra.extend_from_slice(b"abc");
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::TruncatedAddress);

        // Non-UTF-8 domain.
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&53u16.to_be_bytes());
        extra.push(0x02);
        extra.push(2);
        extra.extend_from_slice(&[0xff, 0xfe]);
        let bytes = client_encode::frame(0, 0x02, 0x01, &extra, Some(b"x"));
        assert_eq!(feed_err(&bytes), XudpError::InvalidDomainUtf8);
    }

    #[test]
    fn truncated_frames_at_every_byte_are_safe() {
        // Feeding every strict prefix of a valid frame must either parse
        // partially without emitting or fail cleanly — never panic.
        let bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        for end in 0..bytes.len() {
            let mut decoder = XudpDecoder::new();
            let _ = decoder.feed(&bytes[..end]);
            while decoder.next_frame().is_some() {}
        }
    }

    #[test]
    fn malicious_length_bytes_do_not_allocate() {
        // meta_len 512 of zeros: fixed scratch absorbs it without any
        // payload allocation, then strict parsing rejects it.
        let mut bytes = vec![0x02, 0x00];
        bytes.extend_from_slice(&[0u8; 512]);
        let mut decoder = XudpDecoder::new();
        let result = decoder.feed(&bytes);
        assert!(result.is_err());
    }

    #[test]
    fn mid_frame_reports_eof_position() {
        let bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        let mut decoder = XudpDecoder::new();
        assert!(
            !decoder.mid_frame(),
            "a fresh decoder sits on a frame boundary"
        );

        // Mid-length-field, mid-meta and mid-payload all count as mid-frame.
        decoder.feed(&bytes[..1]).unwrap();
        assert!(decoder.mid_frame());
        decoder.feed(&bytes[1..10]).unwrap();
        assert!(decoder.mid_frame());
        decoder.feed(&bytes[10..bytes.len() - 1]).unwrap();
        assert!(decoder.mid_frame());
        decoder.feed(&bytes[bytes.len() - 1..]).unwrap();
        assert!(!decoder.mid_frame(), "a complete frame ends on a boundary");
        assert!(decoder.next_frame().is_some());
        assert!(!decoder.mid_frame());
    }

    #[test]
    fn frames_completed_before_an_error_stay_queued() {
        // A valid frame followed by garbage in the same feed: the frame is
        // already parsed and must remain deliverable — the error only
        // decides the connection's death, not the datagram's validity.
        let mut bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        bytes.extend_from_slice(&[0x02, 0x01]); // meta_len 513 — fatal
        let mut decoder = XudpDecoder::new();
        let err = decoder
            .feed(&bytes)
            .expect_err("the trailing garbage is fatal");
        assert_eq!(err, XudpError::MetaLenTooLarge(513));
        let frame = decoder.next_frame().expect("the valid frame survives");
        assert!(matches!(frame, XudpFrame::New { .. }));
        assert!(decoder.next_frame().is_none());
    }

    #[test]
    fn metadata_parts_ipv4_split() {
        let target = ipv4_target(203, 0, 113, 7, 853);
        let (ip, host, port) = target.metadata_parts();
        assert_eq!(ip, Some(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 7))));
        assert_eq!(host, "");
        assert_eq!(port, 853);
    }

    // ─── Decoder shapes: KeepAlive, zero-length payloads, sid variety ───

    #[test]
    fn keepalive_with_and_without_data_is_accepted() {
        // Bare keepalive.
        let frames = decode_all(&client_encode::frame(0, 0x04, 0x00, &[], None));
        assert_eq!(
            frames,
            [XudpFrame::KeepAlive {
                session_id: 0,
                payload: None
            }]
        );
        // KeepAlive+Data: payload is read, not rejected — xray discards it.
        let frames = decode_all(&client_encode::frame(0, 0x04, 0x01, &[], Some(b"junk")));
        assert_eq!(
            frames,
            [XudpFrame::KeepAlive {
                session_id: 0,
                payload: Some(Bytes::from_static(b"junk"))
            }]
        );
    }

    #[test]
    fn zero_length_payload_is_a_valid_datagram() {
        let bytes = client_encode::keep_data(3, None, &[]);
        let frames = decode_all(&bytes);
        let XudpFrame::Keep { payload, .. } = &frames[0] else {
            panic!("must be Keep");
        };
        assert_eq!(payload.as_deref(), Some(&[][..]));
    }

    #[test]
    fn nonzero_session_ids_are_accepted() {
        // The spec: never require sid == 0 or sid != 0.
        let bytes = client_encode::keep_data(0xffff, None, b"x");
        let XudpFrame::Keep { session_id, .. } = &decode_all(&bytes)[0] else {
            panic!("must be Keep");
        };
        assert_eq!(*session_id, 0xffff);
    }

    // ─── Session machine: lifecycle ─────────────────────────────────────

    fn new_ipv4_frame(sid: u16, ip: [u8; 4], port: u16, payload: Option<&[u8]>) -> XudpFrame {
        XudpFrame::New {
            session_id: sid,
            network: XudpNetwork::Udp,
            target: ipv4_target(ip[0], ip[1], ip[2], ip[3], port),
            global_id: None,
            payload: payload.map(Bytes::copy_from_slice),
        }
    }

    #[test]
    fn session_lifecycle_new_keep_end() {
        let mut server = XudpServer::new(true);

        // xray style: New+Data — the first datagram rides the New frame.
        let action = server
            .handle_frame(new_ipv4_frame(0, [8, 8, 8, 8], 53, Some(b"first")))
            .unwrap()
            .unwrap();
        let XudpAction::NewSession {
            session_id,
            target,
            global_id,
            first_datagram,
        } = action
        else {
            panic!("must be NewSession");
        };
        assert_eq!(session_id, 0);
        assert_eq!(target, ipv4_target(8, 8, 8, 8, 53));
        assert_eq!(global_id, None);
        assert_eq!(first_datagram.as_deref(), Some(b"first".as_slice()));
        assert!(server.has_session(0));

        // meow style: bare New then Keep+Data.
        let action = server
            .handle_frame(new_ipv4_frame(9, [1, 1, 1, 1], 443, None))
            .unwrap()
            .unwrap();
        assert!(matches!(
            action,
            XudpAction::NewSession {
                first_datagram: None,
                ..
            }
        ));

        // Bare Keep uses the session default target.
        let action = server
            .handle_frame(XudpFrame::Keep {
                session_id: 9,
                target: None,
                payload: Some(Bytes::from_static(b"d")),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            XudpAction::Datagram {
                session_id: 9,
                target: ipv4_target(1, 1, 1, 1, 443),
                payload: Bytes::from_static(b"d"),
            }
        );

        // End tears down; unknown after that.
        let action = server
            .handle_frame(XudpFrame::End {
                session_id: 9,
                error: false,
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            XudpAction::SessionEnd {
                session_id: 9,
                remote_error: false
            }
        );
        assert!(!server.has_session(9));
    }

    #[test]
    fn keep_target_override_does_not_change_the_default() {
        let mut server = XudpServer::new(true);
        server
            .handle_frame(new_ipv4_frame(0, [8, 8, 8, 8], 53, None))
            .unwrap();

        let override_target = domain_target("dns.example.com", 853);
        let action = server
            .handle_frame(XudpFrame::Keep {
                session_id: 0,
                target: Some(override_target.clone()),
                payload: Some(Bytes::from_static(b"q")),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            XudpAction::Datagram {
                session_id: 0,
                target: override_target,
                payload: Bytes::from_static(b"q"),
            }
        );

        // The default target survives the per-packet override.
        assert_eq!(server.default_target(0), Some(&ipv4_target(8, 8, 8, 8, 53)));
        let action = server
            .handle_frame(XudpFrame::Keep {
                session_id: 0,
                target: None,
                payload: Some(Bytes::from_static(b"r")),
            })
            .unwrap()
            .unwrap();
        assert_eq!(
            action,
            XudpAction::Datagram {
                session_id: 0,
                target: ipv4_target(8, 8, 8, 8, 53),
                payload: Bytes::from_static(b"r"),
            }
        );
    }

    #[test]
    fn tcp_new_kills_the_connection() {
        let mut server = XudpServer::new(true);
        let err = server
            .handle_frame(XudpFrame::New {
                session_id: 0,
                network: XudpNetwork::Tcp,
                target: ipv4_target(1, 2, 3, 4, 80),
                global_id: None,
                payload: None,
            })
            .expect_err("TCP New must be fatal");
        assert_eq!(err, XudpError::TcpNewNotPermitted);
        assert_eq!(
            server.active_session_count(),
            0,
            "no session may be created"
        );
    }

    #[test]
    fn duplicate_active_new_is_rejected_but_new_after_end_is_fine() {
        let mut server = XudpServer::new(true);
        server
            .handle_frame(new_ipv4_frame(0, [8, 8, 8, 8], 53, None))
            .unwrap();
        let err = server
            .handle_frame(new_ipv4_frame(0, [1, 1, 1, 1], 53, None))
            .expect_err("duplicate active New must be rejected");
        assert_eq!(err, XudpError::DuplicateSession(0));

        server
            .handle_frame(XudpFrame::End {
                session_id: 0,
                error: false,
            })
            .unwrap();
        server
            .handle_frame(new_ipv4_frame(0, [1, 1, 1, 1], 53, None))
            .expect("New after End reuses the sid cleanly");
    }

    #[test]
    fn unknown_sid_keep_data_gets_an_end_reply_and_drops() {
        let mut server = XudpServer::new(true);
        let action = server
            .handle_frame(XudpFrame::Keep {
                session_id: 42,
                target: None,
                payload: Some(Bytes::from_static(b"late")),
            })
            .unwrap()
            .unwrap();
        assert_eq!(action, XudpAction::ReplyEnd { session_id: 42 });

        // A dataless Keep on the same unknown sid is a complete no-op —
        // xray checks the Data bit before the session lookup.
        let action = server
            .handle_frame(XudpFrame::Keep {
                session_id: 42,
                target: None,
                payload: None,
            })
            .unwrap();
        assert_eq!(action, None);

        // End for a never-opened session is silent too.
        let action = server
            .handle_frame(XudpFrame::End {
                session_id: 42,
                error: true,
            })
            .unwrap();
        assert_eq!(action, None);
    }

    #[test]
    fn keepalive_never_produces_an_action() {
        let mut server = XudpServer::new(true);
        assert_eq!(
            server
                .handle_frame(XudpFrame::KeepAlive {
                    session_id: 0,
                    payload: None
                })
                .unwrap(),
            None
        );
        assert_eq!(
            server
                .handle_frame(XudpFrame::KeepAlive {
                    session_id: 0,
                    payload: Some(Bytes::from_static(b"discard me"))
                })
                .unwrap(),
            None
        );
    }

    #[test]
    fn multi_session_interleaving_stays_isolated() {
        let mut server = XudpServer::new(true);
        server
            .handle_frame(new_ipv4_frame(1, [8, 8, 8, 8], 53, None))
            .unwrap();
        server
            .handle_frame(new_ipv4_frame(2, [1, 1, 1, 1], 443, None))
            .unwrap();

        // Interleaved datagrams route to their own session defaults.
        for (sid, expected) in [
            (1u16, ipv4_target(8, 8, 8, 8, 53)),
            (2u16, ipv4_target(1, 1, 1, 1, 443)),
            (1u16, ipv4_target(8, 8, 8, 8, 53)),
        ] {
            let action = server
                .handle_frame(XudpFrame::Keep {
                    session_id: sid,
                    target: None,
                    payload: Some(Bytes::from_static(b"x")),
                })
                .unwrap()
                .unwrap();
            assert_eq!(
                action,
                XudpAction::Datagram {
                    session_id: sid,
                    target: expected,
                    payload: Bytes::from_static(b"x"),
                }
            );
        }

        // Ending one session leaves the other untouched.
        server
            .handle_frame(XudpFrame::End {
                session_id: 1,
                error: false,
            })
            .unwrap();
        assert!(!server.has_session(1));
        assert!(server.has_session(2));
        assert_eq!(server.active_session_count(), 1);
    }

    #[test]
    fn session_cap_is_enforced() {
        let mut server = XudpServer::new(true);
        for sid in 0..MAX_SESSIONS as u16 {
            server
                .handle_frame(new_ipv4_frame(sid, [10, 0, 0, 1], 53, None))
                .unwrap();
        }
        assert_eq!(server.active_session_count(), MAX_SESSIONS);
        let err = server
            .handle_frame(new_ipv4_frame(200, [10, 0, 0, 1], 53, None))
            .expect_err("session 129 must be refused");
        assert_eq!(err, XudpError::SessionLimitExceeded);
    }

    #[test]
    fn udp_not_permitted_rejects_everything() {
        // Constructed with udp: false, even a perfect New frame is fatal.
        let mut server = XudpServer::new(false);
        let err = server
            .handle_frame(new_ipv4_frame(0, [8, 8, 8, 8], 53, None))
            .expect_err("udp:false must reject");
        assert_eq!(err, XudpError::UdpNotPermitted);
    }

    #[test]
    fn global_id_parsed_but_migration_ignored() {
        let mut server = XudpServer::new(true);
        // Two sequential sessions (via End) with the same GlobalID do not
        // migrate anything: the first session is simply gone.
        let gid = [7u8; 8];
        server
            .handle_frame(XudpFrame::New {
                session_id: 0,
                network: XudpNetwork::Udp,
                target: ipv4_target(8, 8, 8, 8, 53),
                global_id: Some(gid),
                payload: None,
            })
            .unwrap();
        server
            .handle_frame(XudpFrame::End {
                session_id: 0,
                error: false,
            })
            .unwrap();
        let action = server
            .handle_frame(XudpFrame::New {
                session_id: 5,
                network: XudpNetwork::Udp,
                target: ipv4_target(8, 8, 8, 8, 53),
                global_id: Some(gid),
                payload: None,
            })
            .unwrap()
            .unwrap();
        let XudpAction::NewSession { global_id, .. } = action else {
            panic!("must be NewSession");
        };
        // The id is parsed faithfully and exposed — and nothing more:
        // no cross-connection migration, matching mihomo/sing servers.
        assert_eq!(global_id, Some(gid));
        assert!(server.has_session(5));
    }

    // ─── End-to-end: decode bytes → session actions ─────────────────────

    #[test]
    fn golden_bytes_drive_the_session_machine() {
        // xray client shape: New+Data (golden 05), then the golden 06
        // sequence — targeted Keep, bare Keep, End.
        let mut bytes = vectors::decode(vectors::XUDP_NEW_DATA);
        bytes.extend_from_slice(&vectors::decode(vectors::XUDP_KEEP_END));

        let mut decoder = XudpDecoder::new();
        decoder.feed(&bytes).unwrap();
        let mut server = XudpServer::new(true);
        let mut actions = Vec::new();
        while let Some(frame) = decoder.next_frame() {
            if let Some(action) = server.handle_frame(frame).unwrap() {
                actions.push(action);
            }
        }

        assert_eq!(actions.len(), 4);
        assert!(matches!(actions[0], XudpAction::NewSession { .. }));
        assert_eq!(
            actions[1],
            XudpAction::Datagram {
                session_id: 0,
                target: domain_target("dns.example.com", 853),
                payload: Bytes::from_static(b"second-datagram"),
            }
        );
        assert_eq!(
            actions[2],
            XudpAction::Datagram {
                session_id: 0,
                target: ipv4_target(93, 184, 216, 34, 53),
                payload: Bytes::from_static(b"third"),
            }
        );
        assert_eq!(
            actions[3],
            XudpAction::SessionEnd {
                session_id: 0,
                remote_error: false
            }
        );
        assert_eq!(server.active_session_count(), 0);
    }

    #[test]
    fn interleaved_send_receive_shapes_coexist() {
        // Replies are encoded while inbound frames keep arriving — the
        // codec directions are independent objects, so interleaving reply
        // encoding between uplink feeds must not disturb either.
        let uplink = vectors::decode(vectors::XUDP_KEEP_END);
        let source = domain_target("dns.example.com", 853);

        let mut decoder = XudpDecoder::new();
        let mut frames = Vec::new();
        let mut replies = Vec::new();
        for chunk in uplink.chunks(7) {
            decoder.feed(chunk).unwrap();
            while let Some(frame) = decoder.next_frame() {
                frames.push(frame);
            }
            replies.push(encode_reply_keep_data(0, Some(&source), b"reply-bytes").unwrap());
        }
        assert_eq!(frames.len(), 3, "the uplink stream decodes undisturbed");
        assert!(replies.iter().all(|r| r == &replies[0]));
        // And every encoded reply is itself a decodable Keep+Data frame.
        let decoded = decode_all(&replies[0]);
        assert_eq!(decoded.len(), 1);
    }

    #[test]
    fn client_style_new_data_with_global_id_decodes() {
        // xray xudp.PacketWriter shape: first datagram of a target rides
        // New+Data, network UDP, port-first address, trailing GlobalID.
        let target_meta = client_encode::udp_target_meta(53, 0x01, &[93, 184, 216, 34]);
        let gid = [9u8; 8];
        let bytes = client_encode::new_udp_data(0, &target_meta, Some(&gid), b"datagram");
        let frames = decode_all(&bytes);
        let XudpFrame::New {
            network,
            target,
            global_id,
            payload,
            ..
        } = &frames[0]
        else {
            panic!("must be New");
        };
        assert_eq!(*network, XudpNetwork::Udp);
        assert_eq!(*target, ipv4_target(93, 184, 216, 34, 53));
        assert_eq!(*global_id, Some(gid));
        assert_eq!(payload.as_deref(), Some(b"datagram".as_slice()));

        // sing-vmess shape: zero GlobalID is simply not written — no
        // trailing bytes at all.
        let bytes = client_encode::new_udp_data(0, &target_meta, None, b"datagram");
        let XudpFrame::New { global_id, .. } = &decode_all(&bytes)[0] else {
            panic!("must be New");
        };
        assert_eq!(*global_id, None);
    }

    // ─── Domain / IPv6 targets ──────────────────────────────────────────

    #[test]
    fn ipv6_targets_roundtrip() {
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&443u16.to_be_bytes());
        extra.push(0x03);
        extra.extend_from_slice(&[0x20; 16]);
        let bytes = client_encode::frame(0, 0x01, 0x01, &extra, Some(b"v6"));
        let frames = decode_all(&bytes);
        let XudpFrame::New { target, .. } = &frames[0] else {
            panic!("must be New");
        };
        assert_eq!(
            *target,
            XudpTarget {
                addr: XudpAddr::Ipv6(Ipv6Addr::from([0x20; 16])),
                port: 443
            }
        );
        let (ip, host, port) = target.metadata_parts();
        assert_eq!(ip, Some(IpAddr::V6(Ipv6Addr::from([0x20; 16]))));
        assert_eq!(host, "");
        assert_eq!(port, 443);
    }

    #[test]
    fn domain_targets_preserve_wire_bytes() {
        let mut extra = vec![0x02u8];
        extra.extend_from_slice(&853u16.to_be_bytes());
        extra.push(0x02);
        extra.push(15);
        extra.extend_from_slice(b"DNS.Example.COM");
        let bytes = client_encode::frame(0, 0x01, 0x01, &extra, Some(b"x"));
        let frames = decode_all(&bytes);
        let XudpFrame::New { target, .. } = &frames[0] else {
            panic!("must be New");
        };
        // No lowercasing, no normalization inside the codec: tunnel rule
        // matching normalization is the wiring's business.
        let (ip, host, port) = target.metadata_parts();
        assert_eq!(ip, None);
        assert_eq!(host, "DNS.Example.COM");
        assert_eq!(port, 853);
    }

    // ─── Reply encoding shapes ──────────────────────────────────────────

    #[test]
    fn reply_encoding_covers_ip_and_domain_sources() {
        let payload = b"p";
        // IPv4 source.
        let src = ipv4_target(9, 9, 9, 9, 53);
        let frame = encode_reply_keep_data(7, Some(&src), payload).unwrap();
        let frames = decode_all(&frame);
        let XudpFrame::Keep {
            session_id,
            target,
            payload: p,
        } = &frames[0]
        else {
            panic!("must be Keep");
        };
        assert_eq!(*session_id, 7);
        assert_eq!(target.as_ref().unwrap(), &src);
        assert_eq!(p.as_deref(), Some(payload.as_slice()));

        // IPv6 source.
        let src = XudpTarget {
            addr: XudpAddr::Ipv6(Ipv6Addr::LOCALHOST),
            port: 853,
        };
        let frame = encode_reply_keep_data(7, Some(&src), payload).unwrap();
        let frames = decode_all(&frame);
        let XudpFrame::Keep { target, .. } = &frames[0] else {
            panic!("must be Keep");
        };
        assert_eq!(target.as_ref().unwrap(), &src);

        // Bare reply: meta_len 4, no source.
        let frame = encode_reply_keep_data(7, None, payload).unwrap();
        assert_eq!(&frame[..2], &4u16.to_be_bytes());
    }

    #[test]
    fn reply_encoding_rejects_oversize_payload_and_bad_domain() {
        let big = vec![0u8; MAX_PAYLOAD_LEN + 1];
        assert!(encode_reply_keep_data(0, None, &big).is_none());
        assert!(encoded_reply_keep_data_len(None, big.len()).is_none());
        let exact = vec![0u8; MAX_PAYLOAD_LEN];
        assert!(encode_reply_keep_data(0, None, &exact).is_some());

        let long_domain = XudpTarget {
            addr: XudpAddr::Domain(SmolStr::new("a".repeat(256))),
            port: 53,
        };
        assert!(encode_reply_keep_data(0, Some(&long_domain), b"x").is_none());
        assert!(encoded_reply_keep_data_len(Some(&long_domain), 1).is_none());
        let empty_domain = XudpTarget {
            addr: XudpAddr::Domain(SmolStr::default()),
            port: 53,
        };
        assert!(encode_reply_keep_data(0, Some(&empty_domain), b"x").is_none());
    }

    #[test]
    fn encoded_reply_length_matches_every_source_shape_exactly() {
        for payload_len in [0usize, 1, MAX_PAYLOAD_LEN] {
            let payload = vec![0u8; payload_len];
            let sources = [
                None,
                Some(ipv4_target(9, 9, 9, 9, 53)),
                Some(XudpTarget {
                    addr: XudpAddr::Ipv6(Ipv6Addr::LOCALHOST),
                    port: 853,
                }),
                Some(domain_target("dns.example.com", 853)),
                Some(domain_target(&"d".repeat(255), 853)),
            ];
            for source in sources {
                let frame = encode_reply_keep_data(7, source.as_ref(), &payload).unwrap();
                assert_eq!(
                    encoded_reply_keep_data_len(source.as_ref(), payload_len),
                    Some(frame.len()),
                    "precheck length must be the exact encoded frame length"
                );
            }
        }
    }

    #[test]
    fn end_frame_encoding_bytes() {
        let frame = encode_end(0x1234, false);
        assert_eq!(frame.as_ref(), &[0x00, 0x04, 0x12, 0x34, 0x03, 0x00]);
        let frame = encode_end(0x1234, true);
        assert_eq!(frame.as_ref(), &[0x00, 0x04, 0x12, 0x34, 0x03, 0x02]);
    }

    // ─── reply_source: the freedom rewrite rule ─────────────────────────

    #[test]
    fn reply_source_rewrites_dialed_ip_back_to_domain() {
        let target = domain_target("dns.example.com", 853);
        let dialed: IpAddr = "1.2.3.4".parse().unwrap();
        let actual: SocketAddr = "1.2.3.4:853".parse().unwrap();
        let src = reply_source(&target, Some(dialed), actual);
        assert_eq!(src, domain_target("dns.example.com", 853));

        // Reply from a *different* IP — not the dialed one — stays an IP.
        let actual: SocketAddr = "5.6.7.8:853".parse().unwrap();
        let src = reply_source(&target, Some(dialed), actual);
        assert_eq!(src, ipv4_target(5, 6, 7, 8, 853));

        // Dialed IP unknown (proxied outbound): bare IP source.
        let actual: SocketAddr = "1.2.3.4:853".parse().unwrap();
        let src = reply_source(&target, None, actual);
        assert_eq!(src, ipv4_target(1, 2, 3, 4, 853));

        // IP-literal targets never rewrite.
        let target = ipv4_target(1, 2, 3, 4, 853);
        let src = reply_source(&target, Some(dialed), actual);
        assert_eq!(src, ipv4_target(1, 2, 3, 4, 853));

        // The port always comes from the real reply, even on a rewrite.
        let target = domain_target("dns.example.com", 853);
        let actual: SocketAddr = "1.2.3.4:1053".parse().unwrap();
        let src = reply_source(&target, Some(dialed), actual);
        assert_eq!(src, domain_target("dns.example.com", 1053));
    }

    // ─── encode → decode round trips ────────────────────────────────────

    #[test]
    fn meow_client_encoder_output_decodes_and_routes() {
        // The spec requires accepting meow's own client shape — bare New
        // then Keep+Data. Verify against the real client encoders, not
        // hand-rolled bytes.
        let mut stream = Vec::new();
        stream.extend_from_slice(
            &crate::mux::muxcool::encode_new_frame(9, true, "1.1.1.1", 53).expect("new encodes"),
        );
        stream.extend_from_slice(&crate::mux::muxcool::encode_udp_data_frame(
            9,
            b"query",
            "1.1.1.1".parse().unwrap(),
            53,
        ));
        stream.extend_from_slice(&crate::mux::muxcool::encode_keepalive_frame());
        stream.extend_from_slice(&crate::mux::muxcool::encode_end_frame(9, false));

        let mut decoder = XudpDecoder::new();
        decoder.feed(&stream).unwrap();
        let mut server = XudpServer::new(true);
        let mut actions = Vec::new();
        while let Some(frame) = decoder.next_frame() {
            if let Some(action) = server.handle_frame(frame).unwrap() {
                actions.push(action);
            }
        }
        assert_eq!(actions.len(), 3, "NewSession + Datagram + SessionEnd");
        assert!(matches!(
            &actions[0],
            XudpAction::NewSession {
                session_id: 9,
                first_datagram: None,
                ..
            }
        ));
        assert_eq!(
            actions[1],
            XudpAction::Datagram {
                session_id: 9,
                target: ipv4_target(1, 1, 1, 1, 53),
                payload: Bytes::from_static(b"query"),
            }
        );
        assert_eq!(
            actions[2],
            XudpAction::SessionEnd {
                session_id: 9,
                remote_error: false
            }
        );
    }

    #[test]
    fn end_frames_decode_back() {
        let frames = decode_all(&encode_end(3, true));
        assert_eq!(
            frames,
            [XudpFrame::End {
                session_id: 3,
                error: true
            }]
        );
    }
}
