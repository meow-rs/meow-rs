//! First-bytes sniffing for inbounds that hand [`crate::tcp::handle_tcp`] a
//! raw netstack stream (meow-android's tun2socks).
//!
//! The listener-side `SnifferRuntime` peeks a kernel socket; a userspace
//! netstack stream has no `peek`, so here the client's first bytes are
//! read, parsed, and replayed to the upstream ahead of the rest of the
//! stream. Only flows the tunnel cannot otherwise name are touched: every
//! other flow is returned unread, so its routing and timing are unchanged.

use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use meow_common::sniffer::{sniff_http, sniff_tls};
use meow_common::{Metadata, ProxyConn};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, ReadBuf};

use crate::TunnelInner;

/// How long an unnamed flow may stay silent before it is dialed without a
/// name. A client-first protocol sends its first segment right after the
/// handshake ACK; 200 ms is mihomo's pre-dial peek window and the TUN
/// listener's (`TUN_SNIFF_WINDOW`).
const SNIFF_WINDOW: Duration = Duration::from_millis(200);
/// Most bytes gathered while waiting for a ClientHello split across
/// segments. Matches the listener sniffer's peek buffer.
const SNIFF_CAP: usize = 8192;

/// Recover a name for a flow whose destination the tunnel cannot map back
/// (a stale address in our fake-IP range, or another resolver's fake IP in
/// 198.18.0.0/15), from the TLS SNI or HTTP `Host` the client sends first.
///
/// A found name lands in `metadata.sniff_host`, which
/// [`TunnelInner::pre_handle_metadata`] then dials instead of the literal.
/// Bytes read while sniffing are replayed by the returned stream before
/// anything else, so the upstream sees the flow unchanged. A read error or
/// EOF ends sniffing early and the relay meets it on its next read.
pub async fn sniff_unnamed<C>(
    tunnel: &TunnelInner,
    mut conn: C,
    metadata: &mut Metadata,
) -> Box<dyn ProxyConn>
where
    C: ProxyConn + 'static,
{
    if !tunnel.needs_sniffed_name(metadata) {
        return Box::new(conn);
    }
    let prefix = read_first_bytes(&mut conn, SNIFF_WINDOW).await;
    if let Some(name) = sniff_tls(&prefix).or_else(|| sniff_http(&prefix)) {
        metadata.sniff_host = name;
    }
    if prefix.is_empty() {
        return Box::new(conn);
    }
    Box::new(PrefixedConn {
        prefix,
        pos: 0,
        inner: conn,
    })
}

/// Read the client's first bytes within `window`. Keeps reading while the
/// buffer holds the start of a TLS record that is not complete yet; any
/// other payload parses on the first chunk. A read dropped at the deadline
/// consumes nothing (the `AsyncRead` contract for `Pending`).
async fn read_first_bytes<R>(conn: &mut R, window: Duration) -> Vec<u8>
where
    R: AsyncRead + Unpin + ?Sized,
{
    let deadline = tokio::time::Instant::now() + window;
    let mut buf = vec![0u8; SNIFF_CAP];
    let mut n = 0;
    while n < buf.len() {
        match tokio::time::timeout_at(deadline, conn.read(&mut buf[n..])).await {
            Ok(Ok(0) | Err(_)) | Err(_) => break,
            Ok(Ok(read)) => n += read,
        }
        if !tls_record_incomplete(&buf[..n]) {
            break;
        }
    }
    buf.truncate(n);
    buf
}

/// The buffer is a handshake record (0x16, TLS major version 3) whose
/// header or declared body has not fully arrived.
fn tls_record_incomplete(buf: &[u8]) -> bool {
    match buf {
        [0x16] => true,
        [0x16, 0x03, rest @ ..] => {
            rest.len() < 3 || buf.len() < 5 + usize::from(u16::from_be_bytes([buf[3], buf[4]]))
        }
        _ => false,
    }
}

/// `inner` with the bytes consumed while sniffing replayed first.
struct PrefixedConn<C> {
    prefix: Vec<u8>,
    pos: usize,
    inner: C,
}

impl<C: AsyncRead + Unpin> AsyncRead for PrefixedConn<C> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.pos < this.prefix.len() {
            let rest = &this.prefix[this.pos..];
            let n = rest.len().min(buf.remaining());
            buf.put_slice(&rest[..n]);
            this.pos += n;
            if this.pos == this.prefix.len() {
                // Free the sniff buffer for the rest of the flow.
                this.prefix = Vec::new();
                this.pos = 0;
            }
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut this.inner).poll_read(cx, buf)
    }
}

impl<C: AsyncWrite + Unpin> AsyncWrite for PrefixedConn<C> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

impl<C: ProxyConn> ProxyConn for PrefixedConn<C> {
    fn remote_destination(&self) -> String {
        self.inner.remote_destination()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreHandleVerdict, Tunnel};
    use meow_common::{DnsMode, Network};
    use meow_dns::fakeip::{MemoryStore, Pool};
    use meow_dns::Resolver;
    use meow_trie::DomainTrie;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// The mobile clients' setup: own fake-IP pool 28.0.0.0/8, so a
    /// 198.18.x destination can only be another resolver's fake IP.
    fn mobile_tunnel() -> Tunnel {
        let mut resolver = Resolver::new(
            vec![],
            vec![],
            DnsMode::FakeIp,
            DomainTrie::new(),
            true,
            true,
        );
        let net = "28.0.0.0/8".parse().unwrap();
        let pool = Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap();
        resolver.set_fakeip_v4(Arc::new(pool));
        Tunnel::new(Arc::new(resolver))
    }

    fn tcp_to(ip: Ipv4Addr, port: u16) -> Metadata {
        Metadata {
            network: Network::Tcp,
            dst_ip: Some(IpAddr::V4(ip)),
            dst_port: port,
            ..Default::default()
        }
    }

    const SURGE_FAKE_IP: Ipv4Addr = Ipv4Addr::new(198, 18, 1, 220);

    /// A minimal TLS ClientHello record carrying `sni`.
    fn client_hello(sni: &str) -> Vec<u8> {
        let name = sni.as_bytes();
        let mut ext = vec![0x00, 0x00];
        ext.extend_from_slice(&u16::try_from(name.len() + 5).unwrap().to_be_bytes());
        ext.extend_from_slice(&u16::try_from(name.len() + 3).unwrap().to_be_bytes());
        ext.push(0x00);
        ext.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        ext.extend_from_slice(name);

        let mut hello = vec![0x03, 0x03];
        hello.extend_from_slice(&[0u8; 32]);
        hello.extend_from_slice(&[0x00, 0x00, 0x02, 0x00, 0x2f, 0x01, 0x00]);
        hello.extend_from_slice(&u16::try_from(ext.len()).unwrap().to_be_bytes());
        hello.extend_from_slice(&ext);

        let mut handshake = vec![0x01];
        handshake.extend_from_slice(&u32::try_from(hello.len()).unwrap().to_be_bytes()[1..]);
        handshake.extend_from_slice(&hello);

        let mut record = vec![0x16, 0x03, 0x01];
        record.extend_from_slice(&u16::try_from(handshake.len()).unwrap().to_be_bytes());
        record.extend_from_slice(&handshake);
        record
    }

    async fn stream_pair() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (client, server)
    }

    async fn read_exact_from(conn: &mut dyn ProxyConn, len: usize) -> Vec<u8> {
        let mut got = vec![0u8; len];
        conn.read_exact(&mut got).await.unwrap();
        got
    }

    #[tokio::test]
    async fn surge_fake_ip_dials_the_sniffed_sni() {
        let tunnel = mobile_tunnel();
        let (mut client, server) = stream_pair().await;
        let hello = client_hello("account.example.com");
        client.write_all(&hello).await.unwrap();
        client.write_all(b"after").await.unwrap();

        let mut md = tcp_to(SURGE_FAKE_IP, 443);
        let mut conn = sniff_unnamed(tunnel.inner(), server, &mut md).await;
        assert_eq!(md.sniff_host, "account.example.com");

        // The upstream sees the ClientHello first, then the rest.
        let mut want = hello.clone();
        want.extend_from_slice(b"after");
        assert_eq!(read_exact_from(&mut *conn, want.len()).await, want);

        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "account.example.com");
        assert_eq!(md.dst_ip, None, "the foreign fake IP is never dialed");
    }

    #[tokio::test]
    async fn split_client_hello_is_gathered() {
        let tunnel = mobile_tunnel();
        let (mut client, server) = stream_pair().await;
        let hello = client_hello("split.example.com");
        let (head, tail) = hello.split_at(3);
        client.write_all(head).await.unwrap();
        let tail = tail.to_vec();
        tokio::spawn(async move {
            let (mid, rest) = tail.split_at(20);
            tokio::time::sleep(Duration::from_millis(30)).await;
            client.write_all(mid).await.unwrap();
            tokio::time::sleep(Duration::from_millis(30)).await;
            client.write_all(rest).await.unwrap();
        });

        let mut md = tcp_to(SURGE_FAKE_IP, 443);
        let mut conn = sniff_unnamed(tunnel.inner(), server, &mut md).await;
        assert_eq!(md.sniff_host, "split.example.com");
        assert_eq!(read_exact_from(&mut *conn, hello.len()).await, hello);
    }

    #[tokio::test]
    async fn stale_own_fake_ip_is_rescued_by_http_host() {
        let tunnel = mobile_tunnel();
        let (mut client, server) = stream_pair().await;
        let request = b"GET / HTTP/1.1\r\nHost: stale.example.com\r\n\r\n";
        client.write_all(request).await.unwrap();

        // In our range with no live mapping: dropped without a name.
        let mut md = tcp_to(Ipv4Addr::new(28, 0, 0, 9), 80);
        let mut conn = sniff_unnamed(tunnel.inner(), server, &mut md).await;
        assert_eq!(md.sniff_host, "stale.example.com");
        assert_eq!(read_exact_from(&mut *conn, request.len()).await, request);
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "stale.example.com");
    }

    #[tokio::test]
    async fn named_and_real_destinations_are_not_read() {
        let tunnel = mobile_tunnel();
        let mapped = tunnel
            .resolver()
            .lookup_ipv4("mapped.example.com")
            .await
            .unwrap();
        let IpAddr::V4(mapped) = mapped else {
            panic!("v4 pool hands out v4 addresses");
        };
        for dst in [mapped, Ipv4Addr::new(93, 184, 216, 34)] {
            let (mut client, server) = stream_pair().await;
            let hello = client_hello("other.example.com");
            client.write_all(&hello).await.unwrap();

            let mut md = tcp_to(dst, 443);
            let mut conn = sniff_unnamed(tunnel.inner(), server, &mut md).await;
            assert_eq!(md.sniff_host, "", "{dst} needs no sniffed name");
            assert_eq!(read_exact_from(&mut *conn, hello.len()).await, hello);
        }
    }

    #[tokio::test]
    async fn silent_client_dials_after_the_window_without_losing_bytes() {
        let tunnel = mobile_tunnel();
        let (mut client, server) = stream_pair().await;
        let mut md = tcp_to(SURGE_FAKE_IP, 22);

        let start = tokio::time::Instant::now();
        let mut conn = sniff_unnamed(tunnel.inner(), server, &mut md).await;
        let waited = start.elapsed();
        assert!(waited >= SNIFF_WINDOW, "waited {waited:?}");
        assert!(waited < SNIFF_WINDOW * 3, "waited {waited:?}");
        assert_eq!(md.sniff_host, "");

        client.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        assert_eq!(read_exact_from(&mut *conn, 16).await, b"SSH-2.0-client\r\n");
        // No name: the literal is kept, exactly as before.
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.dst_ip, Some(IpAddr::V4(SURGE_FAKE_IP)));
    }

    #[test]
    fn tls_record_incomplete_cases() {
        let hello = client_hello("example.com");
        assert!(tls_record_incomplete(&hello[..1]));
        assert!(tls_record_incomplete(&hello[..4]));
        assert!(tls_record_incomplete(&hello[..hello.len() - 1]));
        assert!(!tls_record_incomplete(&hello));
        assert!(!tls_record_incomplete(b"GET / HTTP/1.1\r\n"));
        assert!(!tls_record_incomplete(&[0x16, 0x01, 0x00]));
    }
}
