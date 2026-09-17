//! Relay proxy group (M1.C-2) — chains multiple outbounds in sequence.
//!
//! Traffic flow: `client → proxy[0] → proxy[1] → … → proxy[N-1] → target`.
//!
//! # Dial algorithm
//!
//! - `proxy[0]`: `dial_tcp(meta_for_proxy[1])` — real TCP connect targeting the
//!   next hop's address.
//! - `proxy[1..N-2]`: `connect_over(stream, meta_for_proxy[i+1])` — proxy-level
//!   CONNECT tunnel through the already-established stream.
//! - `proxy[N-1]`: `connect_over(stream, final_target)` — final hop connects to
//!   the actual target.
//!
//! Nested relay-of-relay works at any chain position: `flatten_hops` splices
//! a nested `RelayGroup`'s resolved members into the outer chain in place, so
//! the preceding hop dials the inner chain's entry point and each inner member
//! runs `connect_over` like any other hop.
//!
//! upstream: adapter/outbound/relay.go

use super::dialer_proxy::DialerProxyAdapter;
use async_trait::async_trait;
use meow_common::{
    AdapterType, MeowError, Metadata, Proxy, ProxyAdapter, ProxyConn, ProxyHealth, ProxyPacketConn,
    Result,
};
use smol_str::SmolStr;
use std::sync::Arc;
use tracing::debug;

// ─── Helpers ─────────────────────────────────────────────────────────────────

/// Build a `Metadata` that targets the given proxy's `server:port`.
///
/// `proxy.addr()` returns `"host:port"` for all adapter types; we parse it
/// here rather than adding a separate port accessor to the trait.
///
/// Note: `rfind(':')` is intentional — it correctly handles IPv6 literal
/// addresses (e.g. `[2001:db8::1]:1080`) by splitting at the *last* colon,
/// so the port is always the suffix after the rightmost colon.
fn metadata_for_proxy(proxy: &Arc<dyn Proxy>) -> Metadata {
    let addr = proxy.addr();
    // IP literals land in `dst_ip` so the preceding hop encodes a typed
    // address (ATYP 1/4, SocksAddr::Ip) rather than a domain name that
    // happens to look like one.  `conn_type` is explicit `Inner`:
    // `Metadata::default()` yields `ConnType::Http`, but this is an internal
    // chained dial — rules, /connections, and stats must not classify it as
    // an HTTP inbound.  Same rule `ProxyDialer::dial` applies (review B2).
    let (host, port) = if let Some(colon) = addr.rfind(':') {
        (
            &addr[..colon],
            addr[colon + 1..].parse::<u16>().unwrap_or(0),
        )
    } else {
        // Addr with no port (e.g. DIRECT ""). Relay treats it as port 0;
        // DIRECT's connect_over ignores the metadata anyway.
        (addr, 0)
    };
    // Strip brackets so `[2001:db8::1]` parses as an IpAddr too.
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    match bare.parse::<std::net::IpAddr>() {
        Ok(ip) => Metadata {
            network: meow_common::Network::Tcp,
            conn_type: meow_common::ConnType::Inner,
            dst_ip: Some(ip),
            dst_port: port,
            ..Default::default()
        },
        Err(_) => Metadata {
            network: meow_common::Network::Tcp,
            conn_type: meow_common::ConnType::Inner,
            host: host.into(),
            dst_port: port,
            ..Default::default()
        },
    }
}

/// Resolve a group hop to the concrete proxy selected for this connection.
///
/// Groups may contain other groups, so keep unwrapping until a leaf (or an
/// adapter without an active member) is reached.  Resolve once before dialing
/// so stateful selectors such as load-balance use the same member for both the
/// preceding hop's target and their own `connect_over` call.
fn resolve_proxy(mut proxy: Arc<dyn Proxy>, metadata: &Metadata) -> Arc<dyn Proxy> {
    while let Some(selected) = proxy.unwrap_proxy(metadata) {
        if Arc::ptr_eq(&proxy, &selected) {
            break;
        }
        proxy = selected;
    }
    proxy
}

/// Resolve every hop once and splice nested relay groups' resolved members
/// into the chain in place.
///
/// `resolve_proxy` cannot see through a nested `RelayGroup` (it is a leaf to
/// `unwrap_proxy`), and a group hop has no `addr()` of its own — the address
/// the preceding hop must dial is the *entry point* of the inner chain.  By
/// flattening, `outer = [X, inner[p, q], Y]` becomes `[X, p, q, Y]`: X dials
/// p's server, then each hop runs `connect_over` in order — exactly mihomo's
/// composed-dialer semantics.  Resolving members here (once) also keeps
/// stateful selectors coherent: the member the preceding hop dials is the
/// same member whose `connect_over` runs.
///
/// A `dialer-proxy` hop whose inner adapter is itself a `RelayGroup` is
/// flattened the same way — inside a chain the per-outbound dialer is
/// ignored by design (`DialerProxyAdapter::connect_over` delegates to the
/// inner adapter), so the member effectively *is* the inner chain.
fn flatten_hops(proxies: &[Arc<dyn Proxy>], metadata: &Metadata) -> Result<Vec<Arc<dyn Proxy>>> {
    flatten_hops_at(proxies, metadata, 0)
}

/// Recursion bound for [`flatten_hops`]: expansion past this depth is a hard
/// error — far beyond any sane config (config resolution already guarantees
/// the group graph is a DAG; the bound stops pathological hand-built graphs).
const MAX_FLATTEN_DEPTH: usize = 16;

fn flatten_hops_at(
    proxies: &[Arc<dyn Proxy>],
    metadata: &Metadata,
    depth: usize,
) -> Result<Vec<Arc<dyn Proxy>>> {
    let mut out = Vec::with_capacity(proxies.len());
    for proxy in proxies {
        let resolved = resolve_proxy(Arc::clone(proxy), metadata);
        if let Some(relay) = resolved
            .as_any()
            .and_then(|a| a.downcast_ref::<RelayGroup>())
        {
            if depth >= MAX_FLATTEN_DEPTH {
                return Err(MeowError::Proxy(format!(
                    "relay: group expansion exceeds depth {MAX_FLATTEN_DEPTH}"
                )));
            }
            out.extend(flatten_hops_at(&relay.proxies, metadata, depth + 1)?);
            continue;
        }
        // Peel `DialerProxyAdapter` layers to reach an inner `RelayGroup`
        // (DPA(DPA(relay)) …).  Each `resolve_proxy` call re-enters the
        // unwrap chain because a DPA delegates `unwrap_proxy` to its inner;
        // a peel that lands on a leaf keeps the ORIGINAL member below.  Not
        // reachable from parsed configs — the dialer-proxy pass always wraps
        // a leaf — but keeps hand-built graphs consistent.
        //
        // Guard: at the very first hop the DPA's own `dial_tcp` must run so
        // its configured front dialer still fires, so only peel when the
        // member lands at a non-first flattened position.
        if !(depth == 0 && out.is_empty()) {
            let mut peeled = Arc::clone(&resolved);
            while let Some(inner) = peeled
                .as_any()
                .and_then(|a| a.downcast_ref::<DialerProxyAdapter>())
                .map(|dpa| Arc::clone(dpa.inner()))
            {
                peeled = resolve_proxy(inner, metadata);
            }
            if let Some(relay) = peeled.as_any().and_then(|a| a.downcast_ref::<RelayGroup>()) {
                if depth >= MAX_FLATTEN_DEPTH {
                    return Err(MeowError::Proxy(format!(
                        "relay: group expansion exceeds depth {MAX_FLATTEN_DEPTH}"
                    )));
                }
                out.extend(flatten_hops_at(&relay.proxies, metadata, depth + 1)?);
                continue;
            }
        }
        out.push(resolved);
    }
    Ok(out)
}

/// Return the target for a hop, skipping later DIRECT hops because they are
/// transparent no-ops inside an already-established relay stream.  Members
/// with no dialable address (`addr() == ""`, e.g. REJECT or an unresolvable
/// group) are skipped for metadata purposes too — the preceding hop would
/// otherwise be told to dial `""`, and the skipped member still gets its own
/// `connect_over` call so it fails at its own hop index rather than
/// misattributing the failure to an earlier hop.
fn metadata_for_next_hop(
    proxies: &[Arc<dyn Proxy>],
    start: usize,
    final_target: &Metadata,
) -> Metadata {
    proxies[start..]
        .iter()
        .find(|proxy| proxy.adapter_type() != AdapterType::Direct && !proxy.addr().is_empty())
        .map_or_else(|| final_target.clone(), metadata_for_proxy)
}

// ─── Core relay functions ─────────────────────────────────────────────────────

/// Establish a TCP relay chain.
///
/// `proxies` must have length ≥ 2 (validated at parse time; `debug_assert`
/// guards against test-harness mistakes).
pub(crate) async fn relay_tcp(
    proxies: &[Arc<dyn Proxy>],
    final_target: &Metadata,
) -> Result<Box<dyn ProxyConn>> {
    debug_assert!(
        proxies.len() >= 2,
        "relay chain must have at least 2 proxies"
    );

    let proxies = flatten_hops(proxies, final_target)?;
    if proxies.len() < 2 {
        return Err(MeowError::Proxy(format!(
            "relay: chain resolved to fewer than 2 hops ({})",
            proxies.len()
        )));
    }

    // proxy[0]: real TCP connect; target = the next non-DIRECT proxy's
    // server:port, or the final destination if only DIRECT hops remain.
    let meta = metadata_for_next_hop(&proxies, 1, final_target);
    debug!(
        relay.hop = 0,
        relay.proxy = proxies[0].name(),
        relay.target = %meta.remote_address(),
        "relay: dial_tcp hop 0"
    );
    let mut conn: Box<dyn ProxyConn> =
        proxies[0]
            .dial_tcp(&meta)
            .await
            .map_err(|e| MeowError::RelayHopFailed {
                hop: 0,
                source: Box::new(e),
            })?;

    // proxy[1..N-2]: connect_over through the previous hop's stream.
    for i in 1..proxies.len() - 1 {
        let meta = metadata_for_next_hop(&proxies, i + 1, final_target);
        debug!(
            relay.hop = i,
            relay.proxy = proxies[i].name(),
            relay.target = %meta.remote_address(),
            "relay: connect_over hop {i}"
        );
        conn =
            proxies[i]
                .connect_over(conn, &meta)
                .await
                .map_err(|e| MeowError::RelayHopFailed {
                    hop: i,
                    source: Box::new(e),
                })?;
    }

    // proxy[N-1]: final hop connects to the actual target.
    let last = proxies.len() - 1;
    debug!(
        relay.hop = last,
        relay.proxy = proxies[last].name(),
        relay.target = %final_target.remote_address(),
        "relay: connect_over final hop {last}"
    );
    conn = proxies[last]
        .connect_over(conn, final_target)
        .await
        .map_err(|e| MeowError::RelayHopFailed {
            hop: last,
            source: Box::new(e),
        })?;

    Ok(conn)
}

/// Establish a UDP relay chain.
///
/// All chain members must support UDP (`support_udp() == true`) — enforced
/// before calling this function by the caller.
///
/// upstream: adapter/outbound/relay.go — `DialUDP` chains through the same
/// proxies as TCP.  In M1 only `DirectAdapter` implements real UDP; for other
/// proxy types this falls through to their `dial_udp` error.
async fn relay_udp(
    proxies: &[Arc<dyn Proxy>],
    metadata: &Metadata,
) -> Result<Box<dyn ProxyPacketConn>> {
    // For UDP relay we route through the first proxy in the chain.
    // True UDP-over-proxy chaining (e.g. SOCKS5 UDP ASSOCIATE through SS)
    // requires per-protocol UDP framing — deferred to post-M1.
    // For M1, if all hops support UDP the simplest contract is to delegate
    // to the first proxy's dial_udp (Direct adapter, which binds a raw socket).
    proxies[0].dial_udp(metadata).await
}

// ─── RelayGroup ───────────────────────────────────────────────────────────────

/// A relay proxy group: chains ≥2 proxies in sequence.
///
/// upstream: adapter/outbound/relay.go — `Relay`
pub struct RelayGroup {
    name: SmolStr,
    proxies: Vec<Arc<dyn Proxy>>,
    health: ProxyHealth, // for API surface; relay has no self-health-check
}

impl RelayGroup {
    /// Create a new relay group.
    ///
    /// Panics in debug builds if `proxies.len() < 2` — parse-time hard-error
    /// must have been enforced before calling this.
    pub fn new(name: &str, proxies: Vec<Arc<dyn Proxy>>) -> Self {
        debug_assert!(
            proxies.len() >= 2,
            "relay group requires at least 2 proxies; got {}",
            proxies.len()
        );
        Self {
            name: SmolStr::from(name),
            proxies,
            health: ProxyHealth::new(),
        }
    }
}

#[async_trait]
impl ProxyAdapter for RelayGroup {
    fn name(&self) -> &str {
        &self.name
    }

    fn adapter_type(&self) -> AdapterType {
        AdapterType::Relay
    }

    /// Relay groups have no single address — they span a chain.
    fn addr(&self) -> &str {
        ""
    }

    /// Returns `true` only if every chain member supports UDP.
    ///
    /// upstream: relay.go — same check.
    /// NOT just the first hop — partial UDP support is a Class A divergence;
    /// we surface `UdpNotSupported` rather than returning a non-functional conn.
    fn support_udp(&self) -> bool {
        self.proxies.iter().all(|p| p.support_udp())
    }

    async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
        relay_tcp(&self.proxies, metadata).await
    }

    /// Returns `Err(UdpNotSupported)` if any chain member lacks UDP support.
    ///
    /// upstream: relay.go — silently returns a non-functional conn.
    /// NOT a silent failure — Class A ADR-0002.
    async fn dial_udp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
        if !self.support_udp() {
            return Err(MeowError::UdpNotSupported);
        }
        relay_udp(&self.proxies, metadata).await
    }

    // No `connect_over` override: after `flatten_hops` no `RelayGroup` can
    // legitimately appear at a non-first hop (nested relays are spliced in
    // place and over-depth expansion is a hard error), so the trait's
    // default `NotSupported` is the correct failure for any group that
    // still reaches this point — loud, and attributed to its own hop index.

    fn health(&self) -> &ProxyHealth {
        &self.health
    }
}

impl Proxy for RelayGroup {
    fn alive(&self) -> bool {
        self.health.alive()
    }

    fn alive_for_url(&self, _url: &str) -> bool {
        self.health.alive()
    }

    fn last_delay(&self) -> u16 {
        self.health.last_delay()
    }

    fn last_delay_for_url(&self, _url: &str) -> u16 {
        self.health.last_delay()
    }

    fn delay_history(&self) -> Vec<meow_common::DelayHistory> {
        self.health.delay_history()
    }

    /// Lets `flatten_hops` downcast a nested relay hop and splice this
    /// group's resolved members into the outer chain.
    fn as_any(&self) -> Option<&dyn std::any::Any> {
        Some(self)
    }

    fn members(&self) -> Option<Vec<String>> {
        Some(self.proxies.iter().map(|p| p.name().to_string()).collect())
    }
}

// ─── Tests ────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SelectorGroup;
    use meow_common::{DelayHistory, MeowError, ProxyConn, ProxyHealth, ProxyPacketConn};
    use std::net::SocketAddr;
    use std::sync::Arc;

    // ── MockProxy ──────────────────────────────────────────────────────────

    /// A transparent mock hop.
    ///
    /// - `dial_tcp` opens a `NopConn` and records nothing (hop 0 never visits).
    /// - `connect_over` appends `self.marker` to `visits` and returns the
    ///   stream (or `fail_with` if set). Records `Metadata.host` to
    ///   `last_dial_host` for A5 assertions.
    struct MockProxy {
        proxy_name: String,
        adapter_type: AdapterType,
        /// Pre-formatted `"server:port"` string — avoids a fresh allocation
        /// (and a `Box::leak`) on every `addr()` call.
        addr_str: String,
        health: ProxyHealth,
        udp: bool,
        /// Each `connect_over` call appends `self.marker` here.
        visits: Arc<parking_lot::Mutex<Vec<u8>>>,
        marker: u8,
        /// Each dial call (dial_tcp or connect_over) records the target host.
        last_dial_host: Arc<parking_lot::Mutex<Option<String>>>,
        /// If `Some`, `connect_over` returns this error.
        fail_with: Arc<parking_lot::Mutex<Option<MeowError>>>,
        /// If `Some`, `dial_tcp` returns this error.
        dial_fail_with: Arc<parking_lot::Mutex<Option<MeowError>>>,
    }

    /// Recorded dial target: `host` for domains, `dst_ip` for IP literals —
    /// `metadata_for_proxy` types IP-literal servers as `dst_ip`.
    fn recorded_host(metadata: &Metadata) -> String {
        if metadata.host.is_empty() {
            metadata.dst_ip.map(|ip| ip.to_string()).unwrap_or_default()
        } else {
            metadata.host.to_string()
        }
    }

    impl MockProxy {
        fn new(name: &str, server: &str, port: u16, marker: u8) -> Arc<Self> {
            Arc::new(Self {
                proxy_name: name.to_string(),
                adapter_type: AdapterType::Socks5,
                addr_str: format!("{server}:{port}"),
                health: ProxyHealth::new(),
                udp: false,
                visits: Arc::new(parking_lot::Mutex::new(Vec::new())),
                marker,
                last_dial_host: Arc::new(parking_lot::Mutex::new(None)),
                fail_with: Arc::new(parking_lot::Mutex::new(None)),
                dial_fail_with: Arc::new(parking_lot::Mutex::new(None)),
            })
        }

        fn new_udp(name: &str, server: &str, port: u16, marker: u8) -> Arc<Self> {
            let m = Self::new(name, server, port, marker);
            // SAFETY: only called at construction before sharing.
            let inner = Arc::try_unwrap(m).ok().unwrap();
            Arc::new(Self { udp: true, ..inner })
        }

        fn no_udp(name: &str, server: &str, port: u16, marker: u8) -> Arc<Self> {
            Self::new(name, server, port, marker) // udp defaults to false
        }

        fn direct() -> Arc<Self> {
            let proxy = Self::new("DIRECT", "", 0, 0);
            let inner = Arc::try_unwrap(proxy).ok().unwrap();
            Arc::new(Self {
                adapter_type: AdapterType::Direct,
                addr_str: String::new(),
                ..inner
            })
        }

        fn failing(name: &str, server: &str, port: u16, err: MeowError) -> Arc<Self> {
            let m = Self::new(name, server, port, 0);
            *m.fail_with.lock() = Some(err);
            m
        }

        fn dial_failing(name: &str, server: &str, port: u16, err: MeowError) -> Arc<Self> {
            let m = Self::new(name, server, port, 0);
            *m.dial_fail_with.lock() = Some(err);
            m
        }
    }

    // ── NopConn ────────────────────────────────────────────────────────────

    /// A `ProxyConn` that accepts all writes and returns EOF on reads.
    struct NopConn;

    impl tokio::io::AsyncRead for NopConn {
        fn poll_read(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            _buf: &mut tokio::io::ReadBuf<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(())) // EOF
        }
    }

    impl tokio::io::AsyncWrite for NopConn {
        fn poll_write(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
            buf: &[u8],
        ) -> std::task::Poll<std::io::Result<usize>> {
            std::task::Poll::Ready(Ok(buf.len()))
        }

        fn poll_flush(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }

        fn poll_shutdown(
            self: std::pin::Pin<&mut Self>,
            _cx: &mut std::task::Context<'_>,
        ) -> std::task::Poll<std::io::Result<()>> {
            std::task::Poll::Ready(Ok(()))
        }
    }

    impl Unpin for NopConn {}
    impl ProxyConn for NopConn {}

    // ── NopPacketConn ──────────────────────────────────────────────────────

    struct NopPacketConn;

    #[async_trait]
    impl ProxyPacketConn for NopPacketConn {
        async fn read_packet(&self, _buf: &mut [u8]) -> Result<(usize, SocketAddr)> {
            Err(MeowError::NotSupported("nop".into()))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> Result<usize> {
            Ok(buf.len())
        }
        fn local_addr(&self) -> Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> Result<()> {
            Ok(())
        }
    }

    // ── MockProxy: ProxyAdapter impl ───────────────────────────────────────

    #[async_trait]
    impl ProxyAdapter for MockProxy {
        fn name(&self) -> &str {
            &self.proxy_name
        }
        fn adapter_type(&self) -> AdapterType {
            self.adapter_type
        }
        fn addr(&self) -> &str {
            &self.addr_str
        }
        fn support_udp(&self) -> bool {
            self.udp
        }

        async fn dial_tcp(&self, metadata: &Metadata) -> Result<Box<dyn ProxyConn>> {
            *self.last_dial_host.lock() = Some(recorded_host(metadata));
            if let Some(err) = self.dial_fail_with.lock().take() {
                return Err(err);
            }
            Ok(Box::new(NopConn))
        }

        async fn dial_udp(&self, _metadata: &Metadata) -> Result<Box<dyn ProxyPacketConn>> {
            if self.udp {
                Ok(Box::new(NopPacketConn))
            } else {
                Err(MeowError::NotSupported("mock: no UDP".into()))
            }
        }

        async fn connect_over(
            &self,
            stream: Box<dyn ProxyConn>,
            metadata: &Metadata,
        ) -> Result<Box<dyn ProxyConn>> {
            *self.last_dial_host.lock() = Some(recorded_host(metadata));
            self.visits.lock().push(self.marker);
            if let Some(err) = self.fail_with.lock().take() {
                return Err(err);
            }
            Ok(stream)
        }

        fn health(&self) -> &ProxyHealth {
            &self.health
        }
    }

    impl Proxy for MockProxy {
        fn alive(&self) -> bool {
            true
        }
        fn alive_for_url(&self, _url: &str) -> bool {
            true
        }
        fn last_delay(&self) -> u16 {
            0
        }
        fn last_delay_for_url(&self, _url: &str) -> u16 {
            0
        }
        fn delay_history(&self) -> Vec<DelayHistory> {
            vec![]
        }
    }

    // ─── A. TCP relay chain — connect_over traversal ──────────────────────

    // A1: two-hop chain — A.dial_tcp, B.connect_over
    // upstream: adapter/outbound/relay.go::DialContext
    // NOT direct connection to target — A receives meta_for_B as its target.
    #[tokio::test]
    async fn relay_two_hop_tcp_roundtrip() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let a_visits = Arc::clone(&a.visits);
        let b_visits = Arc::clone(&b.visits);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("two-hop", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&meta).await.expect("relay_two_hop");

        // A used dial_tcp, NOT connect_over — visits must be empty.
        assert!(
            a_visits.lock().is_empty(),
            "hop 0 must use dial_tcp, NOT connect_over; A.visits={:?}",
            a_visits.lock()
        );
        // B used connect_over exactly once.
        assert_eq!(
            *b_visits.lock(),
            vec![2],
            "hop 1 must call connect_over once; B.visits={:?}",
            b_visits.lock()
        );
    }

    // A2: three-hop chain — A.dial_tcp, B.connect_over, C.connect_over
    #[tokio::test]
    async fn relay_three_hop_tcp_roundtrip() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let c = MockProxy::new("C", "10.0.0.3", 1080, 3);
        let a_visits = Arc::clone(&a.visits);
        let b_visits = Arc::clone(&b.visits);
        let c_visits = Arc::clone(&c.visits);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = RelayGroup::new("three-hop", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&meta).await.expect("relay_three_hop");

        assert!(a_visits.lock().is_empty(), "A.visits must be empty");
        assert_eq!(*b_visits.lock(), vec![2], "B.visits == [2]");
        assert_eq!(*c_visits.lock(), vec![3], "C.visits == [3]");
    }

    // A3: guard-rail — first hop uses dial_tcp, NOT connect_over
    #[tokio::test]
    async fn relay_first_hop_uses_dial_tcp_not_connect_over() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let a_visits = Arc::clone(&a.visits);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("guard-dial-tcp", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&meta).await.unwrap();

        assert!(
            a_visits.lock().is_empty(),
            "hop 0 MUST NOT call connect_over; found visits={:?}",
            a_visits.lock()
        );
    }

    // A4: guard-rail — intermediate hops use connect_over, not dial_tcp
    #[tokio::test]
    async fn relay_intermediate_hops_use_connect_over() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let c = MockProxy::new("C", "10.0.0.3", 1080, 3);
        let a_visits = Arc::clone(&a.visits);
        let b_visits = Arc::clone(&b.visits);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = RelayGroup::new("guard-connect-over", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&meta).await.unwrap();

        assert!(a_visits.lock().is_empty(), "A must NOT use connect_over");
        assert!(
            !b_visits.lock().is_empty(),
            "B (middle hop) MUST use connect_over"
        );
    }

    // A5: guard-rail — each hop receives the NEXT hop's address as its dial target
    // For chain [A→B→C→target]:
    //   A.dial_tcp receives meta with host="10.0.0.2" (B's server)
    //   B.connect_over receives meta with host="10.0.0.3" (C's server)
    //   C.connect_over receives meta with host="target.example"
    #[tokio::test]
    async fn relay_each_hop_receives_next_hop_address() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1081, 2);
        let c = MockProxy::new("C", "10.0.0.3", 1082, 3);
        let a_host = Arc::clone(&a.last_dial_host);
        let b_host = Arc::clone(&b.last_dial_host);
        let c_host = Arc::clone(&c.last_dial_host);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = RelayGroup::new("hop-address-check", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&meta).await.unwrap();

        // A must be called with B's server address.
        assert_eq!(
            *a_host.lock(),
            Some("10.0.0.2".into()),
            "A must receive B's host; got {:?}",
            a_host.lock()
        );
        // B must be called with C's server address.
        assert_eq!(
            *b_host.lock(),
            Some("10.0.0.3".into()),
            "B must receive C's host; got {:?}",
            b_host.lock()
        );
        // C (final hop) must receive the actual target.
        assert_eq!(
            *c_host.lock(),
            Some("target.example".into()),
            "C must receive final target; got {:?}",
            c_host.lock()
        );
    }

    #[tokio::test]
    async fn relay_resolves_group_at_later_hop() {
        let entry = MockProxy::new("entry", "10.0.0.1", 1080, 1);
        let exit = MockProxy::new("exit", "10.0.0.2", 1081, 2);
        let entry_host = Arc::clone(&entry.last_dial_host);
        let exit_host = Arc::clone(&exit.last_dial_host);
        let exit_visits = Arc::clone(&exit.visits);
        let exit_group: Arc<dyn Proxy> = Arc::new(SelectorGroup::new("exit-group", vec![exit]));

        let group = RelayGroup::new("group-hop", vec![entry, exit_group]);
        let target = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&target).await.expect("group relay hop");

        assert_eq!(*entry_host.lock(), Some("10.0.0.2".into()));
        assert_eq!(*exit_host.lock(), Some("target.example".into()));
        assert_eq!(*exit_visits.lock(), vec![2]);
    }

    /// `metadata_for_proxy` must type IP-literal server addrs as `dst_ip`
    /// (ATYP 1/4 / SocksAddr::Ip for the preceding hop's CONNECT) rather
    /// than stuffing them into `host` as pseudo-domains.
    #[test]
    fn metadata_for_proxy_types_ip_literals_as_dst_ip() {
        let p: Arc<dyn Proxy> = MockProxy::new("ip-hop", "203.0.113.7", 8443, 1);
        let m = metadata_for_proxy(&p);
        assert_eq!(m.dst_ip, Some("203.0.113.7".parse().expect("v4")));
        assert!(m.host.is_empty());
        assert_eq!(m.dst_port, 8443);
        assert_eq!(m.network, meow_common::Network::Tcp);
        // Internal chained dial, not an HTTP inbound.
        assert_eq!(m.conn_type, meow_common::ConnType::Inner);
    }

    #[test]
    fn metadata_for_proxy_strips_ipv6_brackets_into_dst_ip() {
        let p: Arc<dyn Proxy> = MockProxy::new("v6-hop", "[2001:db8::1]", 1080, 1);
        let m = metadata_for_proxy(&p);
        assert_eq!(m.dst_ip, Some("2001:db8::1".parse().expect("v6")));
        assert_eq!(m.dst_port, 1080);
    }

    /// `addr()` is always `format!("{server}:{port}")`, so even an
    /// unbracketed IPv6 server like `"2001:db8::1"` yields
    /// `"2001:db8::1:1080"` — `rfind(':')` still isolates the true port and
    /// the remainder parses as an `IpAddr`.  Pin that invariant.
    #[test]
    fn metadata_for_proxy_unbracketed_ipv6_server() {
        let p: Arc<dyn Proxy> = MockProxy::new("v6-bare", "2001:db8::1", 1080, 1);
        let m = metadata_for_proxy(&p);
        assert_eq!(m.dst_ip, Some("2001:db8::1".parse().expect("v6")));
        assert_eq!(m.dst_port, 1080);
        assert!(m.host.is_empty());
    }

    #[test]
    fn metadata_for_proxy_keeps_domains_in_host() {
        let p: Arc<dyn Proxy> = MockProxy::new("dns-hop", "example.com", 443, 1);
        let m = metadata_for_proxy(&p);
        assert_eq!(m.host.as_str(), "example.com");
        assert!(m.dst_ip.is_none());
        assert_eq!(m.dst_port, 443);
    }

    /// A nested relay whose members include a selector must resolve that
    /// selector to its leaf before calling `connect_over`, and the nested
    /// group must be *flattened* into the outer chain: `outer = [a,
    /// inner[sel→b, c]]` runs as `[a, b, c]` so that `a` dials the inner
    /// chain's entry point (b's server) rather than the group's own empty
    /// `addr()`.
    #[tokio::test]
    async fn nested_connect_over_resolves_group_members() {
        let a = MockProxy::new("a", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("b", "10.0.0.2", 1081, 2);
        let c = MockProxy::new("c", "10.0.0.3", 1082, 3);
        let a_host = Arc::clone(&a.last_dial_host);
        let b_visits = Arc::clone(&b.visits);
        let b_host = Arc::clone(&b.last_dial_host);
        let c_visits = Arc::clone(&c.visits);
        let c_host = Arc::clone(&c.last_dial_host);
        let sel: Arc<dyn Proxy> = Arc::new(SelectorGroup::new("sel", vec![b]));
        let inner: Arc<dyn Proxy> = Arc::new(RelayGroup::new("inner", vec![sel, c]));
        let outer = RelayGroup::new("outer", vec![a, inner]);
        let target = Metadata {
            host: "t.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        outer.dial_tcp(&target).await.expect("nested relay");

        // `a` dials the inner chain's entry point — b's server, not the
        // relay group's empty addr().
        assert_eq!(*a_host.lock(), Some("10.0.0.2".into()));
        // Inner chain ran sel→b (resolved) as a connect_over hop aimed at
        // c's server, then c as the final hop aimed at the target.
        assert_eq!(*b_visits.lock(), vec![2]);
        assert_eq!(*b_host.lock(), Some("10.0.0.3".into()));
        assert_eq!(*c_visits.lock(), vec![3]);
        assert_eq!(*c_host.lock(), Some("t.example".into()));
    }

    /// A `dialer-proxy` member whose inner outbound is itself a relay group
    /// flattens the same way: `outer = [a, dpa[inner=[p,q]]]` runs as
    /// `[a, p, q]`, so `a` dials the inner chain's entry point (p's server)
    /// rather than the group's empty `addr()`.  The per-outbound dialer is
    /// deliberately unresolvable here — inside a relay chain it must never
    /// be consulted.
    #[tokio::test]
    async fn nested_dialer_proxy_relay_member_flattens_inner_chain() {
        let a = MockProxy::new("a", "10.0.0.1", 1080, 1);
        let p = MockProxy::new("p", "10.0.0.2", 1081, 2);
        let q = MockProxy::new("q", "10.0.0.3", 1082, 3);
        let a_host = Arc::clone(&a.last_dial_host);
        let p_visits = Arc::clone(&p.visits);
        let p_host = Arc::clone(&p.last_dial_host);
        let q_host = Arc::clone(&q.last_dial_host);

        let inner_relay: Arc<dyn Proxy> = Arc::new(RelayGroup::new("inner", vec![p, q]));
        let dpa: Arc<dyn Proxy> = Arc::new(DialerProxyAdapter::new(
            inner_relay,
            crate::dialer::DialerTarget::new(
                "never-resolved",
                crate::dialer::ProxyRegistry::default(),
            ),
        ));
        let outer = RelayGroup::new("outer", vec![a, dpa]);
        let target = Metadata {
            host: "t.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        outer
            .dial_tcp(&target)
            .await
            .expect("dpa-wrapped relay member");

        assert_eq!(*a_host.lock(), Some("10.0.0.2".into()));
        assert_eq!(*p_visits.lock(), vec![2]);
        assert_eq!(*p_host.lock(), Some("10.0.0.3".into()));
        assert_eq!(*q_host.lock(), Some("t.example".into()));
    }

    /// `DPA(DPA(relay))` must peel both wrapper layers — a single-level peel
    /// would retain the outer DPA (empty `addr()`), silently misrouting the
    /// preceding hop's dial to the *next* member's server.
    #[tokio::test]
    async fn nested_dialer_proxy_layers_all_peel_to_inner_relay() {
        let a = MockProxy::new("a", "10.0.0.1", 1080, 1);
        let p = MockProxy::new("p", "10.0.0.2", 1081, 2);
        let q = MockProxy::new("q", "10.0.0.3", 1082, 3);
        let a_host = Arc::clone(&a.last_dial_host);
        let p_visits = Arc::clone(&p.visits);
        let q_host = Arc::clone(&q.last_dial_host);

        let dead = || {
            crate::dialer::DialerTarget::new(
                "never-resolved",
                crate::dialer::ProxyRegistry::default(),
            )
        };
        let relay: Arc<dyn Proxy> = Arc::new(RelayGroup::new("inner", vec![p, q]));
        let dpa_inner: Arc<dyn Proxy> = Arc::new(DialerProxyAdapter::new(relay, dead()));
        let dpa_outer: Arc<dyn Proxy> = Arc::new(DialerProxyAdapter::new(dpa_inner, dead()));
        let outer = RelayGroup::new("outer", vec![a, dpa_outer]);
        let target = Metadata {
            host: "t.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        outer
            .dial_tcp(&target)
            .await
            .expect("doubly-wrapped relay member");

        assert_eq!(*a_host.lock(), Some("10.0.0.2".into()));
        assert_eq!(*p_visits.lock(), vec![2]);
        assert_eq!(*q_host.lock(), Some("t.example".into()));
    }

    /// A `dialer-proxy` member at hop 0 must NOT be peeled — its `dial_tcp`
    /// preserves the configured front dialer. With an unresolvable dialer
    /// the dial must fail loudly, not silently splice the inner chain.
    #[tokio::test]
    async fn dialer_proxy_at_hop0_keeps_its_front_dialer() {
        let p = MockProxy::new("p", "10.0.0.2", 1081, 2);
        let q = MockProxy::new("q", "10.0.0.3", 1082, 3);
        let x = MockProxy::new("x", "10.0.0.4", 1083, 4);
        let p_visits = Arc::clone(&p.visits);

        let relay: Arc<dyn Proxy> = Arc::new(RelayGroup::new("inner", vec![p, q]));
        let dpa: Arc<dyn Proxy> = Arc::new(DialerProxyAdapter::new(
            relay,
            crate::dialer::DialerTarget::new(
                "never-resolved",
                crate::dialer::ProxyRegistry::default(),
            ),
        ));
        let outer = RelayGroup::new("outer", vec![dpa, x]);
        let target = Metadata {
            host: "t.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = outer
            .dial_tcp(&target)
            .await
            .err()
            .expect("hop-0 DPA must run its own dial_tcp and fail on the unresolvable dialer");
        assert!(
            err.to_string().contains("never-resolved") || err.to_string().contains("dialer"),
            "error must name the missing dialer, got: {err}"
        );
        // Peeling would have spliced the inner chain and run `p` — visits
        // must stay empty to prove no splice happened.
        assert!(p_visits.lock().is_empty(), "hop-0 DPA must not be peeled");
    }

    /// Expansion deeper than `MAX_FLATTEN_DEPTH` is a hard error — a
    /// hand-constructed cyclic or absurdly deep group graph must fail the
    /// dial outright, not silently retain an unexpanded relay mid-chain
    /// (which would misroute the preceding hop to the next member's server).
    #[tokio::test]
    async fn flatten_beyond_max_depth_is_a_hard_error() {
        fn leaf(name: &str) -> Arc<dyn Proxy> {
            MockProxy::new(name, "10.0.0.9", 1090, 9)
        }
        // 20-deep nesting exceeds MAX_FLATTEN_DEPTH (16).
        let mut inner: Arc<dyn Proxy> = leaf("leaf0");
        for i in 0..20 {
            inner = Arc::new(RelayGroup::new("r", vec![inner, leaf(&format!("leaf{i}"))]));
        }
        let outer = RelayGroup::new("outer", vec![leaf("a"), inner]);
        let target = Metadata {
            host: "t.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = outer
            .dial_tcp(&target)
            .await
            .err()
            .expect("over-depth expansion must fail");
        assert!(
            err.to_string().contains("depth"),
            "error must name the depth bound, got: {err}"
        );
    }

    #[tokio::test]
    async fn relay_skips_direct_when_choosing_next_hop_target() {
        let entry = MockProxy::new("entry", "10.0.0.1", 1080, 1);
        let exit = MockProxy::new("exit", "10.0.0.2", 1081, 2);
        let entry_host = Arc::clone(&entry.last_dial_host);
        let exit_host = Arc::clone(&exit.last_dial_host);
        let direct: Arc<dyn Proxy> = MockProxy::direct();

        let group = RelayGroup::new("direct-hop", vec![entry, direct, exit]);
        let target = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group.dial_tcp(&target).await.expect("DIRECT relay hop");

        assert_eq!(*entry_host.lock(), Some("10.0.0.2".into()));
        assert_eq!(*exit_host.lock(), Some("target.example".into()));
    }

    #[tokio::test]
    async fn relay_targets_destination_when_direct_is_last_hop() {
        let entry = MockProxy::new("entry", "10.0.0.1", 1080, 1);
        let entry_host = Arc::clone(&entry.last_dial_host);
        let direct: Arc<dyn Proxy> = MockProxy::direct();

        let group = RelayGroup::new("direct-final-hop", vec![entry, direct]);
        let target = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        group
            .dial_tcp(&target)
            .await
            .expect("final DIRECT relay hop");

        assert_eq!(*entry_host.lock(), Some("target.example".into()));
    }

    // ─── B. Parse-time validation ─────────────────────────────────────────
    // These are tested via the config parser (proxy_parser.rs).
    // We add guard-rail variants here for the RelayGroup constructor itself.

    // B-guard: debug_assert fires when proxies.len() < 2 in debug builds
    // (parse-time hard-error handles production; debug_assert catches test mistakes)
    // Cannot be a regular #[test] in release builds — documented as spec guard.
    // See G2 for the grep-based guard-rail.

    // ─── C. UDP relay ─────────────────────────────────────────────────────

    // C1: all chain members support UDP → dial_udp succeeds; support_udp() = true
    #[tokio::test]
    async fn relay_udp_all_support_udp_succeeds() {
        let a = MockProxy::new_udp("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new_udp("B", "10.0.0.2", 1080, 2);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("udp-all", proxies);

        assert!(
            group.support_udp(),
            "support_udp must be true when all hops support UDP"
        );

        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 53,
            ..Default::default()
        };
        group.dial_udp(&meta).await.expect("dial_udp must succeed");
    }

    // C2: proxy at position 0 lacks UDP → Err(UdpNotSupported)
    // upstream: relay.go — silently returns a non-functional conn.
    // NOT a silent failure. ADR-0002 Class A.
    #[tokio::test]
    async fn relay_udp_hop0_lacks_udp_returns_error() {
        let a = MockProxy::no_udp("A", "10.0.0.1", 1080, 1); // no UDP
        let b = MockProxy::new_udp("B", "10.0.0.2", 1080, 2);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("udp-hop0-no-udp", proxies);

        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 53,
            ..Default::default()
        };
        let err = group.dial_udp(&meta).await.err().expect("must error");
        assert!(
            matches!(err, MeowError::UdpNotSupported),
            "must be UdpNotSupported; got {err:?}"
        );
    }

    // C3: middle hop lacks UDP → Err(UdpNotSupported)
    #[tokio::test]
    async fn relay_udp_middle_hop_lacks_udp_returns_error() {
        let a = MockProxy::new_udp("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::no_udp("B", "10.0.0.2", 1080, 2); // no UDP
        let c = MockProxy::new_udp("C", "10.0.0.3", 1080, 3);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = RelayGroup::new("udp-middle-no-udp", proxies);

        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 53,
            ..Default::default()
        };
        let err = group.dial_udp(&meta).await.err().expect("must error");
        assert!(matches!(err, MeowError::UdpNotSupported));
    }

    // C4: last hop lacks UDP → Err(UdpNotSupported)
    #[tokio::test]
    async fn relay_udp_last_hop_lacks_udp_returns_error() {
        let a = MockProxy::new_udp("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::no_udp("B", "10.0.0.2", 1080, 2); // no UDP

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("udp-last-no-udp", proxies);

        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 53,
            ..Default::default()
        };
        let err = group.dial_udp(&meta).await.err().expect("must error");
        assert!(matches!(err, MeowError::UdpNotSupported));
    }

    // C5: support_udp() reflects all members
    #[tokio::test]
    async fn relay_support_udp_requires_all_members() {
        // All support UDP → true
        let proxies_all: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new_udp("A", "10.0.0.1", 1080, 1),
            MockProxy::new_udp("B", "10.0.0.2", 1080, 2),
            MockProxy::new_udp("C", "10.0.0.3", 1080, 3),
        ];
        let group_all = RelayGroup::new("udp-all-3", proxies_all);
        assert!(group_all.support_udp());

        // One lacks UDP → false
        let proxies_one: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new_udp("A", "10.0.0.1", 1080, 1),
            MockProxy::no_udp("B", "10.0.0.2", 1080, 2),
            MockProxy::new_udp("C", "10.0.0.3", 1080, 3),
        ];
        let group_one = RelayGroup::new("udp-one-missing", proxies_one);
        assert!(!group_one.support_udp());
    }

    // ─── D. Error handling — RelayHopFailed ───────────────────────────────

    // D1: proxy[1] fails → RelayHopFailed { hop: 1, .. }
    // NOT a raw inner error. NOT anyhow::Error.
    #[tokio::test]
    async fn relay_hop_failure_includes_hop_index() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::failing("B", "10.0.0.2", 1080, MeowError::Proxy("inner".into()));

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("hop1-fail", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = group.dial_tcp(&meta).await.err().expect("must error");
        assert!(
            matches!(err, MeowError::RelayHopFailed { hop: 1, .. }),
            "error must be RelayHopFailed at hop 1; got {err:?}"
        );
    }

    // D2: proxy[0] dial_tcp fails → RelayHopFailed { hop: 0, .. }
    #[tokio::test]
    async fn relay_first_hop_failure_includes_hop_0() {
        let a = MockProxy::dial_failing(
            "A",
            "10.0.0.1",
            1080,
            MeowError::Proxy("conn refused".into()),
        );
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("hop0-fail", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = group.dial_tcp(&meta).await.err().expect("must error");
        assert!(
            matches!(err, MeowError::RelayHopFailed { hop: 0, .. }),
            "error must be RelayHopFailed at hop 0; got {err:?}"
        );
    }

    // D3: proxy[2] (last) fails in 3-hop chain → RelayHopFailed { hop: 2, .. }
    #[tokio::test]
    async fn relay_last_hop_failure_includes_correct_index() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let c = MockProxy::failing("C", "10.0.0.3", 1080, MeowError::Proxy("timeout".into()));

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let group = RelayGroup::new("hop2-fail", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = group.dial_tcp(&meta).await.err().expect("must error");
        assert!(
            matches!(err, MeowError::RelayHopFailed { hop: 2, .. }),
            "error must be RelayHopFailed at hop 2; got {err:?}"
        );
    }

    // D4: RelayHopFailed.source contains the original inner error
    #[tokio::test]
    async fn relay_hop_failure_source_is_inner_error() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::failing("B", "10.0.0.2", 1080, MeowError::Proxy("inner-msg".into()));

        let proxies: Vec<Arc<dyn Proxy>> = vec![a, b];
        let group = RelayGroup::new("source-check", proxies);
        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };

        let err = group.dial_tcp(&meta).await.err().expect("must error");
        match err {
            MeowError::RelayHopFailed { hop: 1, source } => {
                assert!(
                    matches!(*source, MeowError::Proxy(_)),
                    "source must be inner Proxy error; got {source:?}"
                );
                let msg = source.to_string();
                assert!(
                    msg.contains("inner-msg"),
                    "source message must contain 'inner-msg'; got {msg:?}"
                );
            }
            other => panic!("expected RelayHopFailed {{ hop: 1, .. }}; got {other:?}"),
        }
    }

    // D5: guard-rail — no anyhow at public boundary
    // (verified by the absence of anyhow::Context / .context( in relay.rs;
    // cannot be a #[test] but documented here per test plan G1/D5)
    //
    // grep "anyhow::Context\|\.context(" crates/meow-proxy/src/group/relay.rs
    // must return zero matches.

    // ─── E. Nested relay (relay-of-relay) ─────────────────────────────────

    // E1: outer 2-hop relay where proxy[0] is itself a 2-hop RelayGroup.
    // Effective sequence: A.dial_tcp → B.connect_over → C.connect_over → D.connect_over.
    // MockProxy implements connect_over today; unignored per architect R-M2 review.
    #[tokio::test]
    async fn relay_nested_relay_group() {
        let a = MockProxy::new("A", "10.0.0.1", 1080, 1);
        let b = MockProxy::new("B", "10.0.0.2", 1080, 2);
        let c = MockProxy::new("C", "10.0.0.3", 1080, 3);
        let d = MockProxy::new("D", "10.0.0.4", 1080, 4);
        let b_visits = Arc::clone(&b.visits);
        let c_visits = Arc::clone(&c.visits);
        let d_visits = Arc::clone(&d.visits);

        let inner_proxies: Vec<Arc<dyn Proxy>> = vec![a, b, c];
        let inner_relay: Arc<dyn Proxy> = Arc::new(RelayGroup::new("inner", inner_proxies));

        let outer_proxies: Vec<Arc<dyn Proxy>> = vec![inner_relay, d];
        let outer_group = RelayGroup::new("outer", outer_proxies);

        let meta = Metadata {
            host: "target.example".into(),
            dst_port: 443,
            ..Default::default()
        };
        outer_group.dial_tcp(&meta).await.expect("nested relay");

        assert_eq!(*b_visits.lock(), vec![2]);
        assert_eq!(*c_visits.lock(), vec![3]);
        assert_eq!(*d_visits.lock(), vec![4]);
    }

    // ─── F. AdapterType and ProxyAdapter trait methods ────────────────────

    // F1: adapter_type() == AdapterType::Relay
    #[test]
    fn adapter_type_is_relay() {
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new("A", "10.0.0.1", 1080, 1),
            MockProxy::new("B", "10.0.0.2", 1080, 2),
        ];
        let group = RelayGroup::new("f1", proxies);
        assert_eq!(group.adapter_type(), AdapterType::Relay);
    }

    // F2: AdapterType::Relay serialises to "Relay" in JSON
    #[test]
    fn adapter_type_serialises_to_relay() {
        let json = serde_json::to_string(&AdapterType::Relay).unwrap();
        assert_eq!(json, r#""Relay""#);
    }

    // F3: group.name() returns the config name
    #[test]
    fn group_name_returns_config_name() {
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new("A", "10.0.0.1", 1080, 1),
            MockProxy::new("B", "10.0.0.2", 1080, 2),
        ];
        let group = RelayGroup::new("my-relay", proxies);
        assert_eq!(group.name(), "my-relay");
    }

    // F4: group.addr() returns ""
    #[test]
    fn group_addr_returns_empty() {
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new("A", "10.0.0.1", 1080, 1),
            MockProxy::new("B", "10.0.0.2", 1080, 2),
        ];
        let group = RelayGroup::new("f4", proxies);
        assert_eq!(group.addr(), "");
    }

    // F5: group.health() is accessible (does not panic)
    #[test]
    fn group_health_accessible() {
        let proxies: Vec<Arc<dyn Proxy>> = vec![
            MockProxy::new("A", "10.0.0.1", 1080, 1),
            MockProxy::new("B", "10.0.0.2", 1080, 2),
        ];
        let group = RelayGroup::new("f5", proxies);
        let _ = group.health(); // must not panic
    }

    // ─── G. Structural invariants ─────────────────────────────────────────

    // G2: debug_assert is present in relay.rs (grep guard-rail)
    // "grep debug_assert crates/meow-proxy/src/group/relay.rs" → non-empty.
    // The parse-time hard-error prevents production use; debug_assert catches
    // test-harness mistakes. Verified: relay_tcp() and RelayGroup::new() both
    // contain debug_assert!(proxies.len() >= 2).

    // G3: connect_over is not defaulted on ProxyAdapter trait — any MockProxy
    // without it would fail to compile. The above MockProxy impl demonstrates
    // that connect_over must be provided explicitly. If omitted, the compiler
    // surfaces a default impl (Err(NotSupported)) — which is intentionally
    // permissive (trait has a default body). The guard-rail is enforced by code
    // review: relay tests MUST use connect_over on every hop and will observe
    // wrong visit counts if connect_over is not called.
}
