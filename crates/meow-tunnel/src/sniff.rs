//! First-bytes sniffing in [`crate::tcp::handle_tcp`], the entry point for
//! inbounds that hand the tunnel a raw netstack stream (the desktop TUN
//! listener, meow-android's tun2socks).
//!
//! The listener-side `SnifferRuntime` peeks a kernel socket; a userspace
//! netstack stream has no `peek`, so here the client's first bytes are
//! read, parsed, and handed to the relay as its prefix, which reaches the
//! upstream ahead of the rest of the stream. Only flows the tunnel cannot
//! otherwise name are read: every other flow keeps its routing and timing.

use std::time::Duration;

use meow_common::sniffer::{sniff_http, sniff_tls};
use meow_common::Metadata;
use tokio::io::{AsyncRead, AsyncReadExt};

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
/// Returns the bytes read, which the caller must relay upstream before
/// anything else; empty, and no allocation, for a flow that needs no name.
/// A read error or EOF ends sniffing early and the relay meets it on its
/// next read.
pub(crate) async fn sniff_unnamed<R>(
    tunnel: &TunnelInner,
    conn: &mut R,
    metadata: &mut Metadata,
) -> Vec<u8>
where
    R: AsyncRead + Unpin + ?Sized,
{
    if !tunnel.needs_sniffed_name(metadata) {
        return Vec::new();
    }
    let prefix = read_first_bytes(conn, SNIFF_WINDOW).await;
    if let Some(name) = sniff_tls(&prefix).or_else(|| sniff_http(&prefix)) {
        metadata.sniff_host = name;
    }
    prefix
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
    // The prefix lives as long as the relay; keep only what was read.
    buf.shrink_to_fit();
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{PreHandleVerdict, Tunnel};
    use meow_common::{ConnType, DnsMode, Network};
    use meow_dns::fakeip::{MemoryStore, Pool};
    use meow_dns::{HostEntry, Resolver};
    use meow_trie::DomainTrie;
    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use tokio::io::AsyncWriteExt;
    use tokio::net::{TcpListener, TcpStream};

    /// The mobile clients' setup: own fake-IP pool 28.0.0.0/8, so a
    /// 198.18.x destination can only be another resolver's fake IP.
    fn mobile_tunnel_with_hosts(hosts: DomainTrie<HostEntry>) -> Tunnel {
        let mut resolver = Resolver::new(vec![], vec![], DnsMode::FakeIp, hosts, true, true);
        let net = "28.0.0.0/8".parse().unwrap();
        let pool = Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap();
        resolver.set_fakeip_v4(Arc::new(pool));
        Tunnel::new(Arc::new(resolver))
    }

    fn mobile_tunnel() -> Tunnel {
        mobile_tunnel_with_hosts(DomainTrie::new())
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

    /// The sniffed prefix followed by the rest of the stream, up to `len`
    /// bytes: what the relay hands the upstream.
    async fn relayed(prefix: Vec<u8>, conn: &mut TcpStream, len: usize) -> Vec<u8> {
        let mut got = prefix;
        let at = got.len();
        got.resize(len, 0);
        conn.read_exact(&mut got[at..]).await.unwrap();
        got
    }

    #[tokio::test]
    async fn surge_fake_ip_sniffs_the_sni() {
        let tunnel = mobile_tunnel();
        let (mut client, mut server) = stream_pair().await;
        let hello = client_hello("account.example.com");
        client.write_all(&hello).await.unwrap();
        client.write_all(b"after").await.unwrap();

        let mut md = tcp_to(SURGE_FAKE_IP, 443);
        let prefix = sniff_unnamed(tunnel.inner(), &mut server, &mut md).await;
        assert_eq!(md.sniff_host, "account.example.com");
        assert!(prefix.starts_with(&hello));

        // The upstream sees the ClientHello first, then the rest.
        let mut want = hello.clone();
        want.extend_from_slice(b"after");
        assert_eq!(relayed(prefix, &mut server, want.len()).await, want);

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
        let (mut client, mut server) = stream_pair().await;
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
        let prefix = sniff_unnamed(tunnel.inner(), &mut server, &mut md).await;
        assert_eq!(md.sniff_host, "split.example.com");
        assert_eq!(prefix, hello);
        assert_eq!(prefix.capacity(), prefix.len(), "sniff buffer trimmed");
    }

    #[tokio::test]
    async fn stale_own_fake_ip_is_rescued_by_http_host() {
        let tunnel = mobile_tunnel();
        let (mut client, mut server) = stream_pair().await;
        let request = b"GET / HTTP/1.1\r\nHost: stale.example.com\r\n\r\n";
        client.write_all(request).await.unwrap();

        // In our range with no live mapping: dropped without a name.
        let mut md = tcp_to(Ipv4Addr::new(28, 0, 0, 9), 80);
        let prefix = sniff_unnamed(tunnel.inner(), &mut server, &mut md).await;
        assert_eq!(md.sniff_host, "stale.example.com");
        assert_eq!(prefix, request);
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.host, "stale.example.com");
    }

    /// A live mapping, a real address and a flow the inbound already
    /// sniffed are left unread: no prefix, no allocation, no wait.
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
        let mut sniffed = tcp_to(SURGE_FAKE_IP, 443);
        sniffed.sniff_host = "inbound.example.com".into();
        for mut md in [
            tcp_to(mapped, 443),
            tcp_to(Ipv4Addr::new(93, 184, 216, 34), 443),
            sniffed,
        ] {
            let (mut client, mut server) = stream_pair().await;
            let hello = client_hello("other.example.com");
            client.write_all(&hello).await.unwrap();

            let before = md.sniff_host.clone();
            let prefix = sniff_unnamed(tunnel.inner(), &mut server, &mut md).await;
            assert_eq!(
                md.sniff_host, before,
                "{:?} needs no sniffed name",
                md.dst_ip
            );
            assert_eq!(prefix.capacity(), 0);
            assert_eq!(relayed(prefix, &mut server, hello.len()).await, hello);
        }
    }

    #[tokio::test]
    async fn silent_client_dials_after_the_window_without_losing_bytes() {
        let tunnel = mobile_tunnel();
        let (mut client, mut server) = stream_pair().await;
        let mut md = tcp_to(SURGE_FAKE_IP, 22);

        let start = tokio::time::Instant::now();
        let prefix = sniff_unnamed(tunnel.inner(), &mut server, &mut md).await;
        let waited = start.elapsed();
        assert!(waited >= SNIFF_WINDOW, "waited {waited:?}");
        assert!(waited < SNIFF_WINDOW * 3, "waited {waited:?}");
        assert_eq!(md.sniff_host, "");
        assert!(prefix.is_empty());

        client.write_all(b"SSH-2.0-client\r\n").await.unwrap();
        assert_eq!(
            relayed(prefix, &mut server, 16).await,
            b"SSH-2.0-client\r\n"
        );
        // No name: the literal is kept, exactly as before.
        assert_eq!(
            tunnel.inner().pre_handle_metadata(&mut md),
            PreHandleVerdict::Continue
        );
        assert_eq!(md.dst_ip, Some(IpAddr::V4(SURGE_FAKE_IP)));
    }

    /// The whole path through `handle_tcp` (meow-android's tun2socks entry):
    /// a flow to a LAN gateway's fake IP routes on the sniffed SNI, IP rules
    /// see that name's real address, DIRECT dials it, and the upstream
    /// receives every byte, the sniffed ClientHello first.
    #[tokio::test]
    async fn handle_tcp_dials_the_sniffed_name_for_a_foreign_fake_ip() {
        let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = echo.local_addr().unwrap().port();
        tokio::spawn(async move {
            let (mut socket, _) = echo.accept().await.unwrap();
            let mut buf = Vec::new();
            socket.read_to_end(&mut buf).await.unwrap();
            socket.write_all(&buf).await.unwrap();
        });

        let mut hosts = DomainTrie::new();
        hosts.insert(
            "account.example.com",
            HostEntry::from(vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]),
        );
        let tunnel = mobile_tunnel_with_hosts(hosts);
        let rules = ["IP-CIDR,198.18.0.0/15,REJECT", "MATCH,DIRECT"]
            .into_iter()
            .map(|line| meow_rules::parse_rule(line, &meow_rules::ParserContext::default()))
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
        tunnel.update_routing(Default::default(), rules, Default::default());
        tunnel.set_connection_notes(true);

        let (mut client, server) = stream_pair().await;
        let md = Metadata {
            conn_type: ConnType::Inner,
            ..tcp_to(SURGE_FAKE_IP, port)
        };
        let inner = tunnel.inner();
        let relay = crate::tcp::handle_tcp(inner, Box::new(server), md);
        let mut sent = client_hello("account.example.com");
        sent.extend_from_slice(b"after");
        let talk = async {
            client.write_all(&sent).await.unwrap();
            client.shutdown().await.unwrap();
            let mut echoed = Vec::new();
            client.read_to_end(&mut echoed).await.unwrap();
            echoed
        };
        let ((), echoed) = tokio::join!(relay, talk);
        assert_eq!(echoed, sent);

        let closed = tunnel.statistics().recently_closed();
        assert_eq!(closed.len(), 1);
        let notes = closed[0].notes.get().unwrap().texts();
        let has = |want: &str| notes.iter().any(|note| note.starts_with(want));
        assert!(
            has("198.18.1.220 is a fake IP from another resolver"),
            "{notes:?}"
        );
        assert!(has("Destination IP for matching: 127.0.0.1"), "{notes:?}");
        assert!(has("Matched rule #2 MATCH → DIRECT"), "{notes:?}");
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
