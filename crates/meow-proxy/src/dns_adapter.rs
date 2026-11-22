//! `type: dns` outbound leaf (issue #974, mihomo's `C.Dns`).
//!
//! A dns node is an in-process resolver endpoint: it never contacts the
//! flow's nominal destination. TCP flows speak RFC 1035 length-prefixed
//! DNS over a `tokio::io::duplex` pipe whose far end
//! [`serve_dns_outbound_stream`] drives; UDP flows enqueue datagrams a
//! single driver task answers serially — no task per packet. Both sides
//! resolve through the shared [`DnsOutboundCell`], so a config reload's
//! new generation — including its enabled bit — reaches live conns, and
//! a disabled or unbound generation answers SERVFAIL rather than any
//! upstream fallback.

use async_trait::async_trait;
use meow_common::{
    AdapterType, ConnType, MeowError, Metadata, ProxyAdapter, ProxyConn, ProxyHealth,
    ProxyPacketConn, Result,
};
use meow_dns::server::{
    answer_outbound_datagram, serve_dns_outbound_stream, DnsOutboundCell, MAX_IN_FLIGHT,
};
use smol_str::SmolStr;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::task::{Context, Poll};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio::sync::{mpsc, Mutex, Semaphore};
use tokio::task::JoinHandle;
use tracing::debug;

/// Headroom for the in-process TCP pipe — comfortably holds a pipelined
/// run of maximal frames so one query never stalls behind duplex
/// back-pressure.
const TCP_PIPE_CAPACITY: usize = 64 * 1024;

/// Bounds on the packet conn's two channels. A full query queue drops
/// the datagram (UDP semantics — the client retries); the reply queue
/// can never outgrow it, since every reply answers an accepted query.
const UDP_QUEUE: usize = 256;

pub struct DnsAdapter {
    name: SmolStr,
    cell: DnsOutboundCell,
    /// Permits shared across every conn this adapter hands out: the same
    /// bound the standalone DNS server puts on upstream-bound queries.
    budget: Arc<Semaphore>,
    health: ProxyHealth,
}

impl DnsAdapter {
    /// `cell` is the config layer's live-resolver indirection — the
    /// adapter resolves the current generation per query rather than
    /// pinning the slot that was installed when it was built, so a
    /// rebuild or `PUT /configs` swap reaches conns already open.
    pub fn new(name: &str, cell: DnsOutboundCell) -> Self {
        Self {
            name: SmolStr::from(name),
            cell,
            budget: Arc::new(Semaphore::new(MAX_IN_FLIGHT)),
            health: ProxyHealth::new(),
        }
    }

    /// Test seam: a shared, saturatable `budget` so conn-drop vs.
    /// permit-wait ordering is observable.
    #[cfg(test)]
    fn with_budget(name: &str, cell: DnsOutboundCell, budget: Arc<Semaphore>) -> Self {
        Self {
            name: SmolStr::from(name),
            cell,
            budget,
            health: ProxyHealth::new(),
        }
    }

    /// A `ConnType::Inner` metadata is the dialer layer asking this leaf
    /// to forward for a chained node — a dns leaf never forwards. The
    /// parser keeps dns nodes out of `dialer-proxy` edges, but a forced
    /// or group-picked path could still reach the dial; fail closed
    /// rather than answer the front's server-bound exchange locally.
    fn reject_inner(&self, metadata: &Metadata) -> Result<()> {
        if metadata.conn_type == ConnType::Inner {
            Err(MeowError::Proxy(format!(
                "dns outbound '{}' cannot carry a dialer-proxy hop",
                self.name
            )))
        } else {
            Ok(())
        }
    }
}

#[async_trait]
impl ProxyAdapter for DnsAdapter {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Dns
    }

    /// No address — the leaf owns no endpoint; `server`/`port` keys are
    /// parser-ignored like mihomo.
    fn addr(&self) -> &str {
        ""
    }

    fn support_udp(&self) -> bool {
        true
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        self.reject_inner(metadata)?;
        let (client, server) = tokio::io::duplex(TCP_PIPE_CAPACITY);
        let cell = Arc::clone(&self.cell);
        let budget = Arc::clone(&self.budget);
        let name = self.name.clone();
        // The serve task is owned by the conn: dropping the client half
        // aborts it even while it parks on an upstream-budget permit —
        // otherwise a dead conn could still spend a freed permit on an
        // upstream query nobody reads (issue #974 review).
        let serve = tokio::spawn(async move {
            if let Err(error) = serve_dns_outbound_stream(server, cell, budget).await {
                debug!("dns outbound '{name}' tcp serve ended: {error}");
            }
        });
        Ok(Box::new(DnsStreamConn {
            stream: client,
            serve,
        }))
    }

    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        self.reject_inner(metadata)?;
        let (query_tx, query_rx) = mpsc::channel(UDP_QUEUE);
        let (reply_tx, reply_rx) = mpsc::channel(UDP_QUEUE);
        let driver = tokio::spawn(run_outbound_datagrams(
            query_rx,
            reply_tx,
            Arc::clone(&self.cell),
            Arc::clone(&self.budget),
        ));
        Ok(Box::new(DnsPacketConn {
            queries: query_tx,
            replies: Mutex::new(reply_rx),
            driver,
            closed: AtomicBool::new(false),
        }))
    }

    async fn connect_over(
        &self,
        _stream: Box<dyn ProxyConn>,
        _metadata: &Metadata,
    ) -> Result<Box<dyn ProxyConn>> {
        Err(MeowError::Proxy(format!(
            "dns outbound '{}' owns no transport — it cannot serve a chained hop",
            self.name
        )))
    }

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

/// The caller half of a `type: dns` outbound's in-process TCP pipe —
/// framed DNS wire bytes; no socket sits underneath. Owns the serve
/// task's handle: dropping the conn aborts the far end so a parked
/// permit wait or in-flight upstream query cannot outlive its client.
struct DnsStreamConn {
    stream: DuplexStream,
    serve: JoinHandle<()>,
}

impl Drop for DnsStreamConn {
    fn drop(&mut self) {
        self.serve.abort();
    }
}

impl ProxyConn for DnsStreamConn {}

impl AsyncRead for DnsStreamConn {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}

impl AsyncWrite for DnsStreamConn {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// One queued UDP DNS exchange: the raw query wire plus the destination
/// the client claimed to send to — the reply reports that address as its
/// source, like a bound datagram socket to the resolver would.
struct UdpQuery {
    wire: Vec<u8>,
    dst: SocketAddr,
}

/// Serially answer the conn's queued datagrams. One task per conn, not
/// per packet: upstream-bound queries still draw from the shared
/// `budget`, but local answers run inline. Exits when the conn's query
/// sender drops (close/drop) or it is aborted.
async fn run_outbound_datagrams(
    mut rx: mpsc::Receiver<UdpQuery>,
    replies: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    cell: DnsOutboundCell,
    budget: Arc<Semaphore>,
) {
    while let Some(query) = rx.recv().await {
        if let Some(reply) = answer_outbound_datagram(&query.wire, &cell, &budget).await {
            // A full reply queue drops like a lost packet — never
            // back-pressure the query loop (issue #974).
            let _ = replies.try_send((reply, query.dst));
        }
    }
}

/// The in-process packet conn a `type: dns` dial hands to the UDP relay.
/// `write_packet` enqueues; the driver answers; `read_packet` dequeues
/// `(reply, claimed-destination)` pairs — the apparent source a client
/// of a real resolver would see.
struct DnsPacketConn {
    queries: mpsc::Sender<UdpQuery>,
    /// `ProxyPacketConn` takes `&self`; the mutex serializes the rare
    /// case of concurrent readers. `recv()` is cancel-safe, so a timed-
    /// out read loses nothing queued.
    replies: Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    driver: JoinHandle<()>,
    closed: AtomicBool,
}

impl Drop for DnsPacketConn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[async_trait]
impl ProxyPacketConn for DnsPacketConn {
    async fn read_packet(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
        let mut rx = self.replies.lock().await;
        match rx.recv().await {
            Some((bytes, dst)) => {
                let n = bytes.len().min(buf.len());
                buf[..n].copy_from_slice(&bytes[..n]);
                Ok((n, dst))
            }
            None => Err(MeowError::Proxy(
                "dns outbound packet conn closed".to_string(),
            )),
        }
    }

    async fn write_packet(&self, buf: &[u8], addr: &SocketAddr) -> Result<usize> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(MeowError::Proxy(
                "dns outbound packet conn closed".to_string(),
            ));
        }
        // `try_send`: a full queue drops the datagram like a lost UDP
        // packet — the stub retries — instead of wedging the session.
        let _ = self.queries.try_send(UdpQuery {
            wire: buf.to_vec(),
            dst: *addr,
        });
        Ok(buf.len())
    }

    /// Unspecified: the conn owns no socket. Consumers keying replies on
    /// the source already skip unspecified addresses.
    fn local_addr(&self) -> Result<SocketAddr> {
        Ok(SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0))
    }

    fn close(&self) -> Result<()> {
        if !self.closed.swap(true, Ordering::Relaxed) {
            // Aborting also drops the reply sender, so a parked
            // `read_packet` wakes to a closed channel instead of hanging
            // until the session reaper arrives.
            self.driver.abort();
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use meow_common::{Metadata, Network};
    use meow_dns::HostEntry;
    use meow_trie::DomainTrie;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// A minimal A query for `example.com` with id `id` — the same wire
    /// shape `meow-dns`'s server tests use.
    fn query(id: u16) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]);
        q.extend_from_slice(&[0x00, 0x01]);
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        q.push(7);
        q.extend_from_slice(b"example");
        q.push(3);
        q.extend_from_slice(b"com");
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // A
        q.extend_from_slice(&1u16.to_be_bytes()); // IN
        q
    }

    /// A minimal A query for `name` — `sample_query`'s shape with a
    /// caller-chosen QNAME (names outside hosts take the upstream path).
    fn query_named(id: u16, name: &str) -> Vec<u8> {
        let mut q = Vec::with_capacity(64);
        q.extend_from_slice(&id.to_be_bytes());
        q.extend_from_slice(&[0x01, 0x00]);
        q.extend_from_slice(&[0x00, 0x01]);
        q.extend_from_slice(&[0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
        for label in name.split('.') {
            q.push(u8::try_from(label.len()).unwrap());
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&1u16.to_be_bytes()); // A
        q.extend_from_slice(&1u16.to_be_bytes()); // IN
        q
    }

    /// A hosts-only resolver answering `example.com` → `ip` locally — no
    /// upstream needed for the outbound's local fast path.
    fn hosts_resolver(ip: IpAddr) -> meow_dns::resolver::Resolver {
        let mut hosts: DomainTrie<HostEntry> = DomainTrie::new();
        hosts.insert("example.com", vec![ip].into());
        meow_dns::resolver::Resolver::new(
            Vec::new(),
            Vec::new(),
            meow_common::DnsMode::Normal,
            hosts,
            true,
            true,
        )
    }

    /// A cell already bound to a hosts-only resolver slot.
    fn bound_cell(ip: IpAddr) -> DnsOutboundCell {
        let cell = meow_dns::new_dns_outbound_cell();
        *cell.write() = Some(meow_dns::new_resolver_slot(Arc::new(hosts_resolver(ip))));
        cell
    }

    fn metadata() -> Metadata {
        Metadata {
            network: Network::Tcp,
            host: "example.com".into(),
            dst_port: 53,
            ..Default::default()
        }
    }

    /// Read one length-prefixed frame off the client half of a TCP dial.
    async fn read_frame(stream: &mut Box<dyn ProxyConn>) -> Vec<u8> {
        let mut prefix = [0u8; 2];
        stream.read_exact(&mut prefix).await.unwrap();
        let mut body = vec![0u8; usize::from(u16::from_be_bytes(prefix))];
        stream.read_exact(&mut body).await.unwrap();
        body
    }

    async fn write_frame(stream: &mut Box<dyn ProxyConn>, body: &[u8]) {
        let len = (body.len() as u16).to_be_bytes();
        stream.write_all(&len).await.unwrap();
        stream.write_all(body).await.unwrap();
        stream.flush().await.unwrap();
    }

    #[test]
    fn adapter_reports_dns_type_with_no_endpoint() {
        let adapter = DnsAdapter::new("dns-out", meow_dns::new_dns_outbound_cell());
        assert_eq!(adapter.adapter_type(), AdapterType::Dns);
        assert_eq!(adapter.name(), "dns-out");
        assert_eq!(adapter.addr(), "");
        assert!(adapter.support_udp());
    }

    #[tokio::test]
    async fn inner_metadata_is_rejected_on_both_dials() {
        let adapter = DnsAdapter::new("dns-out", meow_dns::new_dns_outbound_cell());
        let inner = Metadata {
            conn_type: ConnType::Inner,
            ..metadata()
        };
        assert!(
            adapter.dial_tcp(&inner).await.is_err(),
            "a dns leaf never forwards a dialer-proxy hop"
        );
        assert!(adapter.dial_udp(&inner).await.is_err());
    }

    #[tokio::test]
    async fn tcp_exchange_answers_through_current_generation() {
        let adapter = DnsAdapter::new(
            "dns-out",
            bound_cell(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 9))),
        );
        let mut stream = adapter.dial_tcp(&metadata()).await.unwrap();
        write_frame(&mut stream, &query(0x1234)).await;
        let reply = read_frame(&mut stream).await;
        assert_eq!(&reply[..2], &0x1234u16.to_be_bytes());
        // QR bit set, rcode NOERROR (low nibble of flags byte 2 is clear).
        assert_eq!(reply[2] & 0x80, 0x80);
        assert_eq!(reply[3] & 0x0f, 0);
        // The answer carries the hosts entry's address.
        assert!(reply.windows(4).any(|w| w == [10, 0, 0, 9]), "{reply:02x?}");
    }

    #[tokio::test]
    async fn tcp_exchange_follows_a_generation_swap() {
        let cell = bound_cell(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        let adapter = DnsAdapter::new("dns-out", Arc::clone(&cell));
        let mut stream = adapter.dial_tcp(&metadata()).await.unwrap();
        write_frame(&mut stream, &query(1)).await;
        let first = read_frame(&mut stream).await;
        assert!(first.windows(4).any(|w| w == [10, 0, 0, 1]));
        // A config reload's new slot lands mid-conn — the live query path
        // re-reads the cell per frame.
        *cell.write() = Some(meow_dns::new_resolver_slot(Arc::new(hosts_resolver(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
        ))));
        write_frame(&mut stream, &query(2)).await;
        let second = read_frame(&mut stream).await;
        assert!(second.windows(4).any(|w| w == [10, 0, 0, 2]));
    }

    #[tokio::test]
    async fn unbound_and_disabled_views_answer_servfail() {
        for cell in [meow_dns::new_dns_outbound_cell(), {
            let cell = meow_dns::new_dns_outbound_cell();
            *cell.write() = Some(meow_dns::new_resolver_slot_state(
                Arc::new(hosts_resolver(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)))),
                false,
            ));
            cell
        }] {
            let adapter = DnsAdapter::new("dns-out", cell);
            let mut stream = adapter.dial_tcp(&metadata()).await.unwrap();
            write_frame(&mut stream, &query(7)).await;
            let reply = read_frame(&mut stream).await;
            assert_eq!(reply[3] & 0x0f, 2, "SERVFAIL, never a fallback");
        }
    }

    #[tokio::test]
    async fn udp_exchange_answers_and_echoes_the_claimed_destination() {
        let adapter = DnsAdapter::new(
            "dns-out",
            bound_cell(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 7))),
        );
        let conn = adapter.dial_udp(&metadata()).await.unwrap();
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 53);
        let written = conn.write_packet(&query(0xbeef), &dst).await.unwrap();
        assert_eq!(written, query(0xbeef).len());
        let mut buf = [0u8; 2048];
        let (n, src) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("reply arrives")
        .unwrap();
        assert_eq!(src, dst, "the reply reports the claimed destination");
        assert_eq!(&buf[..2], &0xbeefu16.to_be_bytes());
        assert_eq!(buf[3] & 0x0f, 0, "NOERROR");
        assert!(buf[..n].windows(4).any(|w| w == [10, 0, 0, 7]));
    }

    #[tokio::test]
    async fn udp_unbound_view_answers_servfail() {
        let adapter = DnsAdapter::new("dns-out", meow_dns::new_dns_outbound_cell());
        let conn = adapter.dial_udp(&metadata()).await.unwrap();
        let dst = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(9, 9, 9, 9)), 5353);
        conn.write_packet(&query(8), &dst).await.unwrap();
        let mut buf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            conn.read_packet(&mut buf),
        )
        .await
        .expect("reply arrives")
        .unwrap();
        assert!(n >= 12);
        assert_eq!(buf[3] & 0x0f, 2, "unbound leaf answers SERVFAIL");
    }

    #[tokio::test]
    async fn close_wakes_a_parked_reader() {
        let adapter = DnsAdapter::new("dns-out", meow_dns::new_dns_outbound_cell());
        let conn = adapter.dial_udp(&metadata()).await.unwrap();
        let read = async {
            let mut buf = [0u8; 512];
            conn.read_packet(&mut buf).await
        };
        tokio::pin!(read);
        // Park the reader first — nothing is queued to answer.
        tokio::select! {
            _ = &mut read => panic!("a read must not finish before close"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => {}
        }
        conn.close().unwrap();
        let parked = tokio::time::timeout(std::time::Duration::from_secs(5), &mut read).await;
        assert!(
            parked.expect("close wakes the reader").is_err(),
            "close ends a parked read instead of hanging"
        );
    }

    /// Issue #974 review: dropping the client half aborts the serve task
    /// even while it parks on the shared upstream permit — a dead conn
    /// must not still consume the permit it was waiting for once the
    /// holder releases it. The upstream is a blackhole, so a leaked task
    /// would hold the freed permit for the full query timeout.
    #[tokio::test]
    async fn dropping_tcp_conn_aborts_a_permit_parked_serve() {
        let budget = Arc::new(Semaphore::new(1));
        let held = Arc::clone(&budget).acquire_owned().await.unwrap();
        // Upstream-only resolver: no hosts, a dead upstream — the query
        // below must wait on `budget` before it could ever forward.
        let resolver = meow_dns::resolver::Resolver::new(
            vec!["127.0.0.1:9".parse().unwrap()],
            Vec::new(),
            meow_common::DnsMode::Normal,
            DomainTrie::new(),
            true,
            true,
        );
        let cell = meow_dns::new_dns_outbound_cell();
        *cell.write() = Some(meow_dns::new_resolver_slot(Arc::new(resolver)));
        let adapter = DnsAdapter::with_budget("dns-out", cell, Arc::clone(&budget));

        let mut conn = adapter.dial_tcp(&metadata()).await.unwrap();
        write_frame(&mut conn, &query_named(1, "nowhere.test")).await;
        // Let the serve task read the frame and reach its permit wait.
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert_eq!(budget.available_permits(), 0);
        drop(conn);
        drop(held);
        // If the dropped conn's task were still parked it would now grab
        // the freed permit and pin it against the blackhole upstream.
        tokio::time::sleep(std::time::Duration::from_millis(150)).await;
        assert_eq!(
            budget.available_permits(),
            1,
            "the aborted serve must not consume the freed permit"
        );
    }
}
