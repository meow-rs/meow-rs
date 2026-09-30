//! Snell UDP-over-TCP framing.
//!
//! Port of opensnell `components/snell/udp.go`. Each datagram is sent as a
//! single snell AEAD frame whose body is
//! `[CommandUDPForward=0x01][addr][payload]`. The address encoding mirrors
//! SOCKS5 except IPv6 is signaled by `0x06` (not 0x04 of SOCKS5).
//!
//! Server → client frames use a slightly different address layout:
//! `[0x04|0x06][ip-bytes][port:u16 BE][payload]`. The `read_packet` parser
//! handles both ipv4 (`0x04`) and ipv6 (`0x06`); domain-name replies are not
//! emitted by official servers.

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use async_trait::async_trait;
use meow_common::{MeowError, ProxyPacketConn, Result};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::Mutex;

use super::protocol::{Snell, COMMAND_UDP_FORWARD};

/// Build the `[CommandUDPForward][addr-encoding][payload]` frame payload for a
/// snell UDP request.
fn build_request_frame(addr: &SocketAddr, payload: &[u8]) -> Vec<u8> {
    // Header is encoded as if the client always sent an IP target; that
    // matches what opensnell's PacketConn does after the DNS resolve
    // shortcut in the SOCKS5 path.
    let mut buf = Vec::with_capacity(1 + 1 + 16 + 2 + payload.len());
    buf.push(COMMAND_UDP_FORWARD);
    // host-length 0 means "address follows as raw IP" with a one-byte family
    // marker.
    buf.push(0);
    match addr.ip() {
        IpAddr::V4(v4) => {
            buf.push(0x04);
            buf.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            buf.push(0x06);
            buf.extend_from_slice(&v6.octets());
        }
    }
    buf.extend_from_slice(&addr.port().to_be_bytes());
    buf.extend_from_slice(payload);
    buf
}

/// Parse a server-to-client snell UDP response frame, writing the payload
/// into `out` and returning (bytes copied, source address).
fn parse_response_frame(frame: &[u8], out: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
    if frame.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "snell udp: empty response frame",
        ));
    }

    let (addr, payload_start) = match frame[0] {
        0x04 => {
            const HEAD_LEN: usize = 1 + 4 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv4 response frame",
                ));
            }
            let ip = [frame[1], frame[2], frame[3], frame[4]];
            let port = [frame[5], frame[6]];
            (
                SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        0x06 => {
            const HEAD_LEN: usize = 1 + 16 + 2;
            if frame.len() < HEAD_LEN {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "snell udp: short IPv6 response frame",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&frame[1..17]);
            let port = [frame[17], frame[18]];
            // Dual-stack servers (v6) report IPv4 sources as `::ffff:a.b.c.d`;
            // unmap them so replies match the IPv4 target the caller sent to.
            (
                SocketAddr::new(Ipv6Addr::from(ip).to_canonical(), u16::from_be_bytes(port)),
                HEAD_LEN,
            )
        }
        other => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("snell udp: unknown address family 0x{other:x}"),
            ));
        }
    };

    let payload = &frame[payload_start..];
    let copied = payload.len().min(out.len());
    out[..copied].copy_from_slice(&payload[..copied]);
    Ok((copied, addr))
}

/// Per-connection snell UDP relay. Multiplexes datagrams over a single AEAD
/// stream.
///
/// The AEAD codec keeps its read and write cipher states in one object over
/// one TCP stream, so a `tokio::io::split`-style structural split is not
/// possible. Instead the stream sits behind a synchronous mutex that is
/// locked **per poll** (the same lock-per-poll pattern `tokio::io::split`
/// uses internally): a `read_packet` parked waiting for a server datagram
/// holds no stream lock between polls, so `write_packet` on the same conn
/// proceeds freely (issue #278). The `read_gate`/`write_gate` async mutexes serialise whole
/// datagrams within each direction so concurrent callers cannot interleave
/// partial frames; `read_gate` doubles as the owner of the reusable frame
/// buffer so reads allocate once per conn, not once per datagram.
///
/// A `write_packet` future dropped mid-frame would leave the AEAD stream
/// torn — v4's next write would clobber undrained pending bytes, v3's would
/// append after a half-written frame — silently desyncing every following
/// datagram. `poisoned` + `PoisonOnIncomplete` make the tear fail fast
/// instead (issue #625.3, same pattern as the trojan/vless packet conns).
pub struct SnellPacketConn<S> {
    stream: Arc<parking_lot::Mutex<Snell<S>>>,
    read_gate: Mutex<Vec<u8>>,
    write_gate: Mutex<()>,
    poisoned: AtomicBool,
    /// Largest frame one record carries (v6 allows more than v3/v4).
    max_frame: usize,
}

impl<S> SnellPacketConn<S> {
    pub fn new(snell: Snell<S>) -> Self {
        Self {
            max_frame: snell.max_packet_frame_len(),
            stream: Arc::new(parking_lot::Mutex::new(snell)),
            read_gate: Mutex::new(Vec::new()),
            write_gate: Mutex::new(()),
            poisoned: AtomicBool::new(false),
        }
    }
}

#[async_trait]
impl<S> ProxyPacketConn for SnellPacketConn<S>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + Sync + 'static,
{
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        // No post-lock re-check needed: the read side cannot tear framing —
        // a cancelled read resumes the same frame via the codec's internal
        // state — so the poison can only come from the write side, and a
        // conn with a torn uplink is dead regardless of what the peer sends.
        crate::check_not_desynced(&self.poisoned)?;
        let mut frame = self.read_gate.lock().await;
        // One decoded AEAD frame per `poll_read` ready; the frame buffer is
        // sized so a full frame always fits and never splits across reads.
        // Sized lazily on first use — conns that never receive pay nothing.
        if frame.len() < self.max_frame {
            frame.resize(self.max_frame, 0);
        }
        let n = std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            let mut rb = tokio::io::ReadBuf::new(frame.as_mut_slice());
            match std::pin::Pin::new(&mut *stream).poll_read(cx, &mut rb) {
                std::task::Poll::Ready(Ok(())) => std::task::Poll::Ready(Ok(rb.filled().len())),
                std::task::Poll::Ready(Err(e)) => std::task::Poll::Ready(Err(e)),
                std::task::Poll::Pending => std::task::Poll::Pending,
            }
        })
        .await
        .map_err(MeowError::Io)?;
        parse_response_frame(&frame[..n], buf).map_err(MeowError::Io)
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        crate::check_not_desynced(&self.poisoned)?;
        let _serialized = self.write_gate.lock().await;
        // Re-check after the lock: a write parked behind one cancelled
        // mid-frame must not append after the torn frame.
        crate::check_not_desynced(&self.poisoned)?;
        let frame = build_request_frame(addr, buf);
        // Oversize is rejected before arming the guard — an unwritable
        // datagram must not brick an otherwise healthy conn (the codec's
        // own check inside `poll_write_packet_frame` stays as backstop).
        if frame.len() > self.max_frame {
            return Err(MeowError::Io(io::Error::new(
                io::ErrorKind::InvalidInput,
                "snell: packet frame too large",
            )));
        }
        let mut progress = super::protocol::PacketFrameProgress::default();
        // The guard poisons the conn if this future is dropped or returns
        // an error before completing the frame.
        let mut guard = crate::PoisonOnIncomplete::new(&self.poisoned);
        std::future::poll_fn(|cx| {
            let mut stream = self.stream.lock();
            stream.poll_write_packet_frame(cx, &frame, &mut progress)
        })
        .await
        .map_err(MeowError::Io)?;
        guard.complete = true;
        Ok(buf.len())
    }

    fn local_addr(&self) -> Result<SocketAddr> {
        // Datagrams ride on a TCP stream — no real local UDP socket exists.
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::snell::protocol::RESPONSE_TUNNEL;
    use crate::snell::v3::V3Conn;
    use crate::snell::v4::V4Conn;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::time::timeout;

    /// Regression for issue #278: with a single async mutex held across the
    /// blocking frame read, a parked `read_packet` starved `write_packet`
    /// forever and any send-while-awaiting-reply flow stalled after the
    /// first datagram. The write below must complete while a reader is
    /// parked on an idle stream.
    #[tokio::test]
    async fn write_packet_proceeds_while_read_parked() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = Arc::new(SnellPacketConn::new(Snell::new(a, Arc::clone(&psk))));
        let mut peer = V4Conn::new(b, psk);

        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Park a reader while the stream is idle.
        let reader_conn = Arc::clone(&conn);
        let reader = tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            reader_conn
                .read_packet(&mut buf)
                .await
                .map(|(n, addr)| (buf[..n].to_vec(), addr))
        });
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Old design: deadlocked here (reader held the stream lock).
        timeout(Duration::from_secs(5), conn.write_packet(b"ping", &dst))
            .await
            .expect("write_packet must not deadlock while a read is parked")
            .expect("write_packet");

        // Peer: acknowledge the session, verify the client's request frame,
        // then echo a response frame so the parked reader completes.
        peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
        peer.flush().await.unwrap();
        let mut buf = [0u8; 2048];
        let n = timeout(Duration::from_secs(5), peer.read(&mut buf))
            .await
            .expect("peer read timed out")
            .unwrap();
        assert_eq!(&buf[..n], &build_request_frame(&dst, b"ping")[..]);

        let mut resp = vec![0x04, 9, 9, 9, 9];
        resp.extend_from_slice(&53u16.to_be_bytes());
        resp.extend_from_slice(b"pong");
        peer.write_all(&resp).await.unwrap();
        peer.flush().await.unwrap();

        let (payload, addr) = timeout(Duration::from_secs(5), reader)
            .await
            .expect("parked reader timed out")
            .expect("reader task")
            .expect("read_packet");
        assert_eq!(payload, b"pong");
        assert_eq!(addr, dst);
    }

    /// Issue #625.3: a `write_packet` future dropped mid-frame leaves a torn
    /// AEAD frame on the wire — the next write would append after the torn
    /// prefix (v3) or clobber undrained pending bytes (v4), desyncing every
    /// following datagram silently. The conn must poison instead. Runs on
    /// both codec versions: v3 tears a plain AEAD stream record, v4 a staged
    /// packet frame.
    #[tokio::test]
    async fn cancelled_write_poisons_packet_conn() {
        for versioned in [false, true] {
            let (a, b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let conn = SnellPacketConn::new(if versioned {
                Snell::new_v3(a, Arc::clone(&psk))
            } else {
                Snell::new(a, Arc::clone(&psk))
            });
            let _peer = b;
            let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

            // Tiny pipe: a 4 KiB datagram exceeds the duplex buffer, so the
            // write pends mid-frame with a prefix already on the wire.
            let cancelled = timeout(
                Duration::from_millis(50),
                conn.write_packet(&[0xAA; 4096], &dst),
            )
            .await;
            assert!(
                cancelled.is_err(),
                "v{}: write must have timed out mid-frame",
                if versioned { 3 } else { 4 }
            );
            drop(_peer);

            let err = conn.write_packet(b"x", &dst).await.unwrap_err();
            assert!(
                err.to_string().contains("desynced"),
                "v{}: write after a cancelled write must fail fast, got {err:?}",
                if versioned { 3 } else { 4 }
            );
            let mut buf = [0u8; 64];
            let err = conn.read_packet(&mut buf).await.unwrap_err();
            assert!(
                err.to_string().contains("desynced"),
                "v{}: read after a cancelled write must fail fast, got {err:?}",
                if versioned { 3 } else { 4 }
            );
        }
    }

    /// A `write_packet` cancelled while parked on `write_gate` consumed
    /// nothing — the guard arms only *after* the lock, so it must not
    /// poison the conn. The interrupted first write still completes and a
    /// later datagram goes out on a healthy conn.
    #[tokio::test]
    async fn parked_write_cancellation_does_not_poison_conn() {
        let (a, b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = Arc::new(SnellPacketConn::new(Snell::new(a, Arc::clone(&psk))));
        let mut peer = V4Conn::new(b, psk);
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Occupy the writer mid-frame so the second write parks on the gate.
        let conn2 = Arc::clone(&conn);
        let first = tokio::spawn(async move { conn2.write_packet(&[0xAA; 4096], &dst).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        let conn3 = Arc::clone(&conn);
        let queued = tokio::spawn(async move { conn3.write_packet(b"queued", &dst).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        queued.abort();
        let _ = queued.await;

        // Drain the wire so the first write completes and frees the gate.
        // The drain runs inline via select so `peer` stays alive — a
        // spawned+aborted drainer would drop the peer half and the trailing
        // "after" write could hit a broken pipe on residual ciphertext.
        let mut drain = vec![0u8; 1 << 16];
        timeout(Duration::from_secs(5), async {
            let mut first = std::pin::pin!(first);
            loop {
                tokio::select! {
                    biased;
                    r = &mut first => break r,
                    r = peer.read(&mut drain) => match r {
                        Ok(0) | Err(_) => panic!("peer closed while draining"),
                        Ok(_) => {}
                    },
                }
            }
        })
        .await
        .expect("first write hung")
        .expect("first task")
        .expect("first write must complete once the peer drains");

        // The parked write's cancellation must not have poisoned the conn.
        conn.write_packet(b"after", &dst).await.unwrap();
    }

    /// A `read_packet` dropped mid-frame must resume the same frame: the
    /// codec's `ReaderState` keeps the partial record, so the next call
    /// yields the complete datagram — this is the invariant that lets the
    /// read side skip a poison guard. Runs on both codecs; v3 and v4 keep
    /// read progress in different state machines.
    #[test]
    fn cancelled_read_resumes_same_frame() {
        use std::future::Future;
        use std::task::{Context, Poll};

        for versioned in [false, true] {
            let (a, b) = tokio::io::duplex(1 << 10);
            let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
            let conn = SnellPacketConn::new(if versioned {
                Snell::new_v3(a, Arc::clone(&psk))
            } else {
                Snell::new(a, Arc::clone(&psk))
            });
            let mut cx = Context::from_waker(std::task::Waker::noop());

            // Response: tunnel byte + one complete datagram. Payload sizes
            // keep the whole datagram in ONE record while making its
            // ciphertext exceed the 1 KiB pipe — so both the peer's write
            // and the client's read park mid-record deterministically:
            //   v4: plaintext 808 ≤ first-record limit = 1460 − 55 − padding
            //       with padding ∈ [256,511] → limit ∈ [894,1149];
            //       ciphertext 1119–1374 B (salt 16 + hdr 23 + padding
            //       256–511 + sealed payload 824).
            //   v3: one record per write call; ciphertext ~2041 B.
            let payload_len = if versioned { 2000 } else { 800 };
            let payload = vec![0x5Au8; payload_len];
            let mut resp = vec![RESPONSE_TUNNEL, 0x04, 9, 9, 9, 9];
            resp.extend_from_slice(&53u16.to_be_bytes());
            resp.extend_from_slice(&payload);

            let mut buf = vec![0u8; payload_len + 64];
            macro_rules! run {
                ($peer:expr) => {{
                    let mut peer_write = Box::pin($peer.write_all(&resp));
                    assert!(
                        peer_write.as_mut().poll(&mut cx).is_pending(),
                        "v{}: peer write must park on the tiny pipe",
                        if versioned { 3 } else { 4 }
                    );

                    // First read consumes the partial ciphertext and parks
                    // mid-record; dropping it must not lose the progress.
                    let mut read_fut = Box::pin(conn.read_packet(&mut buf));
                    assert!(read_fut.as_mut().poll(&mut cx).is_pending());
                    drop(read_fut); // cancelled mid-frame

                    // Pump the peer's remaining ciphertext and re-poll fresh
                    // read futures — each resumes the codec's parked state.
                    let mut write_done = false;
                    let mut got = None;
                    for _ in 0..512 {
                        if !write_done {
                            write_done = peer_write.as_mut().poll(&mut cx).is_ready();
                        }
                        let mut read_fut = Box::pin(conn.read_packet(&mut buf));
                        if let Poll::Ready(result) = read_fut.as_mut().poll(&mut cx) {
                            got = Some(result.expect("resumed read"));
                            break;
                        }
                        // Still pending — the dropped future is harmless.
                    }
                    got.unwrap_or_else(|| {
                        panic!(
                            "v{}: resumed read never completed",
                            if versioned { 3 } else { 4 }
                        )
                    })
                }};
            }
            let got = if versioned {
                let mut peer = V3Conn::new(b, psk);
                run!(peer)
            } else {
                let mut peer = V4Conn::new(b, psk);
                run!(peer)
            };
            assert_eq!(&buf[..got.0], &payload[..]);
            assert_eq!(got.1, "9.9.9.9:53".parse().unwrap());
        }
    }

    /// A write parked on `write_gate` while another write is cancelled
    /// mid-frame must fail fast instead of appending after the torn frame.
    #[tokio::test]
    async fn queued_write_after_cancelled_write_fails_fast() {
        let (a, b) = tokio::io::duplex(1 << 10);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = Arc::new(SnellPacketConn::new(Snell::new(a, Arc::clone(&psk))));
        let _peer = V4Conn::new(b, psk);
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Occupy the writer mid-frame.
        let conn2 = Arc::clone(&conn);
        let first = tokio::spawn(async move { conn2.write_packet(&[0xAA; 4096], &dst).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        // Queue a second write behind it, then abort the first mid-frame.
        let conn3 = Arc::clone(&conn);
        let queued = tokio::spawn(async move { conn3.write_packet(b"queued", &dst).await });
        tokio::time::sleep(Duration::from_millis(10)).await;
        first.abort();
        let err = queued.await.unwrap().unwrap_err();
        assert!(
            err.to_string().contains("desynced"),
            "queued write must fail fast after the poisoned first write, got {err:?}"
        );
    }

    /// A datagram too large to frame is a per-packet error — rejected before
    /// the poison guard arms — not a dead conn (issue #625.3, matches the
    /// trojan check-before-guard ordering).
    #[tokio::test]
    async fn oversize_write_does_not_poison_conn() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = SnellPacketConn::new(Snell::new(a, Arc::clone(&psk)));
        let _peer = V4Conn::new(b, psk);
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        // Payload == MAX guarantees frame.len() > MAX after the ~9-byte
        // request header — must error without touching the wire.
        let err = conn
            .write_packet(&vec![0xAA; crate::snell::v4::MAX_PAYLOAD_LENGTH], &dst)
            .await
            .unwrap_err();
        assert!(
            !err.to_string().contains("desynced"),
            "oversize must not desync the conn, got {err:?}"
        );

        // The conn stays usable — a normal datagram still writes fine.
        conn.write_packet(b"ok", &dst).await.unwrap();
    }

    /// Happy-path guard: consecutive complete writes must not poison.
    #[tokio::test]
    async fn completed_writes_leave_conn_usable() {
        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let conn = SnellPacketConn::new(Snell::new(a, Arc::clone(&psk)));
        let mut peer = V4Conn::new(b, psk);
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();

        for i in 0u8..3 {
            conn.write_packet(&[i; 4], &dst).await.unwrap();
        }
        peer.write_all(&[RESPONSE_TUNNEL]).await.unwrap();
        // Two differently-sized response frames back to back pin the reused
        // `read_gate` buffer: the second read must see its own datagram, not
        // stale bytes from the first.
        let mut frame = vec![0x04, 9, 9, 9, 9];
        frame.extend_from_slice(&53u16.to_be_bytes());
        frame.extend_from_slice(b"ok");
        let mut frame2 = vec![0x04, 9, 9, 9, 9];
        frame2.extend_from_slice(&53u16.to_be_bytes());
        frame2.extend_from_slice(b"a-longer-second-reply-payload");
        peer.write_all(&frame).await.unwrap();
        peer.write_all(&frame2).await.unwrap();
        peer.flush().await.unwrap();
        let mut buf = [0u8; 64];
        let (n, _) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ok");
        let (n, _) = conn.read_packet(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"a-longer-second-reply-payload");
    }

    /// v6 records hold up to 0xffff bytes: a datagram past the v3/v4 frame
    /// limit travels whole both ways, and a reply byte sharing a record
    /// with the first datagram is split off correctly.
    #[tokio::test]
    async fn v6_datagrams_exceed_the_v4_frame_limit() {
        use crate::snell::v6::{SnellV6Mode, V6Codec, V6Conn};

        let (a, b) = tokio::io::duplex(1 << 16);
        let psk: Arc<[u8]> = Arc::from(b"test-psk".as_slice());
        let codec = V6Codec::new(SnellV6Mode::Default, &psk);
        let conn = SnellPacketConn::new(Snell::new_v6(a, Arc::clone(&psk), codec.clone()));
        let mut peer = V6Conn::new(b, psk, codec);
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let big = vec![0x5a; crate::snell::v4::MAX_PAYLOAD_LENGTH + 4000];

        let read_one = async {
            let mut frame = vec![0u8; 1 << 16];
            let n = peer.read(&mut frame).await.unwrap();
            frame.truncate(n);
            frame
        };
        let (written, uploaded) = timeout(Duration::from_secs(10), async {
            tokio::join!(conn.write_packet(&big, &dst), read_one)
        })
        .await
        .unwrap();
        assert_eq!(written.unwrap(), big.len());
        assert_eq!(uploaded, build_request_frame(&dst, &big));

        let mut reply = vec![RESPONSE_TUNNEL, 0x04, 9, 9, 9, 9];
        reply.extend_from_slice(&53u16.to_be_bytes());
        reply.extend_from_slice(&big);
        peer.stage_packet_frame(&reply).unwrap();
        peer.flush().await.unwrap();
        let mut buf = vec![0u8; 1 << 16];
        let (n, from) = timeout(Duration::from_secs(10), conn.read_packet(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(from, dst);
        assert!(buf[..n] == big[..]);
    }

    #[test]
    fn request_frame_ipv4_layout() {
        let frame = build_request_frame(&"1.2.3.4:5353".parse().unwrap(), b"\x00\x01");
        assert_eq!(frame[0], COMMAND_UDP_FORWARD);
        assert_eq!(frame[1], 0); // host-length 0 → IP follows
        assert_eq!(frame[2], 0x04);
        assert_eq!(&frame[3..7], &[1, 2, 3, 4]);
        assert_eq!(&frame[7..9], &5353u16.to_be_bytes());
        assert_eq!(&frame[9..], b"\x00\x01");
    }

    #[test]
    fn request_frame_ipv6_layout() {
        let frame = build_request_frame(&"[::1]:53".parse().unwrap(), b"abc");
        assert_eq!(frame[0], COMMAND_UDP_FORWARD);
        assert_eq!(frame[1], 0);
        assert_eq!(frame[2], 0x06);
        assert_eq!(frame.len(), 1 + 1 + 1 + 16 + 2 + 3);
        assert_eq!(&frame[frame.len() - 3..], b"abc");
    }

    #[test]
    fn response_frame_unmaps_ipv4_mapped_sources() {
        let reply = |ip: Ipv6Addr| {
            let mut frame = vec![0x06];
            frame.extend_from_slice(&ip.octets());
            frame.extend_from_slice(&53u16.to_be_bytes());
            frame.extend_from_slice(b"ok");
            frame
        };
        let mut out = [0u8; 8];

        let mapped = Ipv4Addr::new(127, 0, 0, 1).to_ipv6_mapped();
        let (n, from) = parse_response_frame(&reply(mapped), &mut out).unwrap();
        assert_eq!(&out[..n], b"ok");
        assert_eq!(from, "127.0.0.1:53".parse().unwrap());

        let (_, from) = parse_response_frame(&reply(Ipv6Addr::LOCALHOST), &mut out).unwrap();
        assert_eq!(from, "[::1]:53".parse().unwrap());
    }
}
