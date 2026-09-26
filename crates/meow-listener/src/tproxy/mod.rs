mod firewall;
mod orig_dest;
mod udp;

use crate::sniffer::SnifferRuntime;
use firewall::FirewallGuard;
use meow_common::{with_dial_timeout, ConnType, Metadata, Network};
use meow_tunnel::{copy_bidirectional_buf_tracked, ResolvedTarget, Tunnel, RELAY_BUF_SIZE};
use std::collections::HashSet;
use std::future::Future;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Default cap on in-flight inbound connections per listener when the
/// listener config doesn't set `max-connections` (mirrors
/// `mixed::DEFAULT_MAX_CONNECTIONS` — kept as a separate constant rather than
/// an import so `listener-tproxy` stays usable without `listener-mixed`
/// enabled). `0` explicitly disables the cap.
pub const DEFAULT_MAX_CONNECTIONS: usize = 256;

pub struct TProxyListener {
    tunnel: Tunnel,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    routing_mark: Option<u32>,
    name: String,
    max_connections: usize,
    /// Whether meow installs and owns the platform firewall rules
    /// (nftables/pf) for this listener. `false` leaves rule management to
    /// an external system — no `nft`/`pfctl` invocation, no upstream
    /// bypass-IP collection, no rule cleanup on exit (issue #563).
    firewall: bool,
    /// Opt-in Linux UDP TPROXY datagram path on the same port (issue
    /// #564). Requires `firewall: false` — the deployer owns the
    /// PREROUTING TPROXY rules, fwmark, and policy routing.
    udp: bool,
    /// Per-flow UDP idle timeout (both directions refresh it).
    udp_timeout: std::time::Duration,
    /// Fallible setup performed by [`Self::prepare`] — carried so `run_on`
    /// spawns nothing that can fail inside a detached task (issue #641).
    prepared: Option<Prepared>,
}

/// Fallible setup artifacts held on the listener between
/// [`TProxyListener::prepare`] and [`TProxyListener::run_on`]. `Drop` on
/// the firewall guard tears the rules down.
struct Prepared {
    /// Address the setup was performed against — `run_on` asserts the
    /// served socket resolves to the same address so firewall rules and
    /// the transparent UDP socket can't silently land on a different
    /// port than the TCP listener.
    bound_addr: SocketAddr,
    firewall: Option<FirewallGuard>,
    /// Bound `IP_TRANSPARENT` UDP socket (Linux `udp: true` only).
    #[cfg(target_os = "linux")]
    udp_socket: Option<tokio::net::UdpSocket>,
}

impl TProxyListener {
    pub fn new(
        tunnel: Tunnel,
        listen_addr: SocketAddr,
        enable_sni: bool,
        routing_mark: Option<u32>,
        name: String,
    ) -> Self {
        // Deprecated `enable_sni` knob: synthesise a minimal sniffer config.
        let sniffer = if enable_sni {
            warn!(
                "`enable_sni` is deprecated; migrate to the top-level `sniffer:` block. \
                Accepting as `sniffer.enable: true, sniff.TLS.ports: [443]` for this release. \
                Will be removed in a future version."
            );
            let cfg = meow_common::SnifferConfig {
                enable: true,
                tls_ports: vec![443],
                http_ports: Vec::new(),
                ..Default::default()
            };
            Some(Arc::new(SnifferRuntime::new(cfg)))
        } else {
            None
        };
        Self {
            tunnel,
            listen_addr,
            sniffer,
            routing_mark,
            name,
            max_connections: DEFAULT_MAX_CONNECTIONS,
            firewall: true,
            udp: false,
            udp_timeout: std::time::Duration::from_secs(60),
            prepared: None,
        }
    }

    pub fn with_sniffer(mut self, sniffer: Arc<SnifferRuntime>) -> Self {
        if sniffer.is_enabled() {
            self.sniffer = Some(sniffer);
        }
        self
    }

    /// Override the cap on in-flight inbound connections (default
    /// [`DEFAULT_MAX_CONNECTIONS`]). `0` disables the cap.
    pub fn with_max_connections(mut self, max: usize) -> Self {
        self.max_connections = max;
        self
    }

    /// Set `false` to delegate firewall rule management to an external
    /// system (issue #563): the listener only accepts TCP REDIRECT'd
    /// connections and recovers the original destination; no nftables/pf
    /// rules are installed, probed, or cleaned up. Default `true`.
    pub fn with_firewall(mut self, enabled: bool) -> Self {
        self.firewall = enabled;
        self
    }

    /// Enable the Linux UDP TPROXY datagram path on the listener's port
    /// (issue #564). `udp_timeout` is the per-flow idle timeout. Linux-only
    /// and external-firewall-only in this release — both are enforced at
    /// config-parse and again at `run_on`.
    pub fn with_udp(mut self, enabled: bool, udp_timeout: std::time::Duration) -> Self {
        self.udp = enabled;
        self.udp_timeout = udp_timeout;
        self
    }

    pub async fn run(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // Bind first so a port-0 listen can resolve to the OS-assigned port
        // before firewall rules are installed against it.
        let listener = TcpListener::bind(self.listen_addr).await?;
        self.run_on(listener).await
    }

    /// Perform the fallible setup — platform/udp gate checks, managed
    /// firewall rules, and the UDP `IP_TRANSPARENT` socket — eagerly, so a
    /// caller spawning [`Self::run_on`] in a detached task can fail the
    /// listener before the bound TCP socket is handed over (issue #641).
    /// `bound_addr` is the resolved listen addr (post port-0 resolution)
    /// — it must be the `local_addr()` of the socket later passed to
    /// [`Self::run_on`], or the prepared firewall/UDP artifacts would
    /// target a different port than the one accepting TCP (debug-asserted).
    pub async fn prepare(
        mut self,
        bound_addr: SocketAddr,
    ) -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        // Set up firewall redirect rules (tears down on drop) — skipped
        // entirely under external firewall management: no bypass-IP
        // collection, no nft/pfctl invocation, no cleanup ownership
        // (issue #563). An externally-managed listener without rules in
        // place accepts nothing; that is the deployer's contract.
        //
        // `FirewallGuard::setup` doubles as the unsupported-platform gate —
        // `firewall: false` must not smuggle a dead listener onto a platform
        // where orig-dest recovery cannot work, so keep the gate explicit.
        #[cfg(not(any(target_os = "macos", target_os = "linux")))]
        if !self.firewall {
            return Err("transparent proxy is not supported on this platform".into());
        }

        // Validate the UDP opt-in BEFORE any firewall work — an invalid
        // combination must not install-then-remove rules on the way out.
        if self.udp && self.firewall {
            return Err(
                "tproxy `udp: true` requires `firewall: false` — meow does not \
                 manage UDP TPROXY rules/policy routing"
                    .into(),
            );
        }

        let firewall = if self.firewall {
            let bypass_ips = collect_proxy_server_ips(&self.tunnel);
            Some(
                FirewallGuard::setup(bound_addr.port(), self.routing_mark, &bypass_ips).map_err(
                    |e| -> Box<dyn std::error::Error + Send + Sync> {
                        // `firewall: false` is only a remedy where orig-dest
                        // recovery can work — on other platforms the external
                        // gate above refuses too, so don't send users down a
                        // dead end.
                        #[cfg(any(target_os = "macos", target_os = "linux"))]
                        let e = format!(
                            "{e} — to manage firewall rules externally (no nft/pfctl \
                             required), declare this listener under `listeners:` \
                             with `firewall: false`"
                        );
                        e.into()
                    },
                )?,
            )
        } else {
            None
        };

        // #564: opt-in Linux UDP TPROXY datagram path on the same bound
        // port. Both invariants are re-enforced here even though config
        // parsing already rejects `udp` + managed firewall and non-IPv4
        // binds — programmatic constructors get the same contract.
        #[cfg(target_os = "linux")]
        let udp_socket = if self.udp {
            Some(udp::bind_transparent(bound_addr).map_err(
                |e| -> Box<dyn std::error::Error + Send + Sync> {
                    format!(
                        "tproxy `udp` transparent socket on {bound_addr} failed \
                             (needs CAP_NET_ADMIN/CAP_NET_RAW): {e}"
                    )
                    .into()
                },
            )?)
        } else {
            None
        };
        #[cfg(not(target_os = "linux"))]
        if self.udp {
            return Err("tproxy `udp: true` is Linux-only in this release".into());
        }

        self.prepared = Some(Prepared {
            bound_addr,
            firewall,
            #[cfg(target_os = "linux")]
            udp_socket,
        });
        Ok(self)
    }

    /// Serve on an already-bound socket, letting the caller resolve a
    /// `port: 0` ephemeral listener to its OS-assigned port first. Firewall
    /// redirect rules are installed against the socket's actual local port,
    /// so ephemeral listeners redirect correctly. Runs [`Self::prepare`]
    /// internally when the caller didn't — embedders that spawn this in a
    /// detached task should `prepare` first so setup failures surface at
    /// spawn time.
    pub async fn run_on(
        mut self,
        listener: TcpListener,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bound_addr = listener.local_addr().unwrap_or(self.listen_addr);
        if self.prepared.is_none() {
            self = self.prepare(bound_addr).await?;
        }
        let prepared = self.prepared.take().expect("prepare fills the slot");
        debug_assert_eq!(
            prepared.bound_addr, bound_addr,
            "TProxyListener::prepare was run against a different address \
             than the socket passed to run_on — firewall rules/UDP socket \
             would bind the wrong port"
        );
        // The guard keeps the managed ruleset alive for the loop's lifetime.
        let _firewall = prepared.firewall;

        #[cfg(target_os = "linux")]
        if let Some(udp_socket) = prepared.udp_socket {
            let udp_tunnel = self.tunnel.clone();
            let udp_timeout = self.udp_timeout;
            let udp_max = self.max_connections;
            let udp_name = self.name.clone();
            let udp_port = bound_addr.port();
            // `run_udp` retries socket errors internally and only ends
            // via abort — there is no error return to surface here.
            tokio::spawn(async move {
                udp::run_udp(
                    udp_tunnel,
                    udp_socket,
                    udp_timeout,
                    udp_max,
                    udp_name,
                    udp_port,
                )
                .await;
            });
            info!(
                "TProxy listener '{}': UDP TPROXY active on {} (external rules \
                 must steer LAN datagrams here — see docs/tproxy-gateway.md)",
                self.name, bound_addr
            );
        }

        if self.max_connections == 0 {
            info!(
                "TProxy listener '{}' started on {} (max_connections=unlimited)",
                self.name, bound_addr
            );
        } else {
            info!(
                "TProxy listener '{}' started on {} (max_connections={})",
                self.name, bound_addr, self.max_connections
            );
        }

        if !self.firewall {
            info!(
                "TProxy listener '{}': external firewall management — no rules \
                 installed or cleaned up; TCP REDIRECT (and loop-prevention \
                 bypass) is the deployer's responsibility",
                self.name
            );
        }

        // Scope decision for the pf path (#248): the managed ruleset
        // intercepts loopback-traversing IPv4 TCP only; steering real
        // outbound (en0) traffic stays a manual, documented pf detour rather
        // than something meow rewrites the host's pf config for. Surface that
        // at startup so "tproxy is on but my browser isn't proxied" is
        // explained by the log, not a silent surprise. Under external
        // management meow's ruleset isn't installed — the deployer's rules
        // decide the scope, so the note would be misleading.
        #[cfg(target_os = "macos")]
        if self.firewall {
            info!(
                "TProxy on macOS intercepts loopback IPv4 TCP only; real outbound \
                 traffic needs the manual route-to detour (docs/tproxy-macos.md) — \
                 for full transparent proxying use the TUN inbound (docs/tun.md)"
            );
        }

        let tunnel = self.tunnel;
        let sniffer = self.sniffer;
        let name = self.name;
        let max_connections = self.max_connections;
        bounded_accept_loop(listener, max_connections, name.clone(), {
            move |stream, src_addr| {
                let tunnel = tunnel.clone();
                let sniffer = sniffer.clone();
                let name = name.clone();
                async move {
                    if let Err(e) =
                        handle_tproxy_conn(tunnel, stream, src_addr, bound_addr, sniffer, name)
                            .await
                    {
                        debug!("TProxy connection error from {src_addr}: {e}");
                    }
                }
            }
        })
        .await
    }
}

/// Accept loop bounded by an optional `max_connections` semaphore: a permit
/// is acquired *before* `accept()` (back-pressuring the TCP listen queue
/// instead of spawning unboundedly and bloating RSS — issue #435) and
/// released once `handle`'s future completes. `max_connections == 0`
/// disables the cap.
///
/// Extracted as a free function generic over the per-connection handler so
/// the concurrency-cap invariant can be pinned by a unit test (see `tests`
/// below) without needing a live firewall/redirect setup, which
/// [`TProxyListener::run_on`] requires before reaching this loop.
async fn bounded_accept_loop<F, Fut>(
    listener: TcpListener,
    max_connections: usize,
    name: String,
    mut handle: F,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
where
    F: FnMut(TcpStream, SocketAddr) -> Fut,
    Fut: Future<Output = ()> + Send + 'static,
{
    let conn_limit: Option<Arc<Semaphore>> = if max_connections > 0 {
        Some(Arc::new(Semaphore::new(max_connections)))
    } else {
        None
    };
    let mut warned_saturated = false;
    // A persistent accept failure (fd exhaustion) must not spin the loop
    // or flood the log; a transient one must not be delayed meaningfully.
    let mut accept_backoff = meow_common::ErrorBackoff::new();

    loop {
        let permit = if let Some(sem) = &conn_limit {
            let sem = Arc::clone(sem);
            if sem.available_permits() == 0 && !warned_saturated {
                warn!(
                    "TProxy listener '{}' saturated at {} concurrent connections; new clients will queue",
                    name, max_connections
                );
                warned_saturated = true;
            }
            match sem.acquire_owned().await {
                Ok(p) => {
                    if warned_saturated {
                        debug!("TProxy listener '{}' has free capacity again", name);
                        warned_saturated = false;
                    }
                    Some(p)
                }
                Err(_) => return Ok(()), // semaphore closed → shutdown
            }
        } else {
            None
        };

        // Log, back off, and continue on accept errors (matching mixed.rs)
        // rather than propagating: a transient EMFILE/ECONNABORTED must not
        // tear down `run_on`'s `_firewall` guard and take the redirect rules
        // with it. Loud only when the backoff engaged (socket-level failure,
        // error! so fd-exhaustion events are visible at default log levels);
        // per-connection errors are queue progress and stay at debug!.
        let (stream, src_addr) = match listener.accept().await {
            Ok(v) => {
                accept_backoff.succeeded();
                v
            }
            Err(e) => {
                drop(permit);
                if accept_backoff.failed(&e).await {
                    error!("TProxy listener '{}' accept error: {e}", name);
                } else {
                    debug!("TProxy listener '{}' accept error: {e}", name);
                }
                continue;
            }
        };

        let fut = handle(stream, src_addr);
        tokio::spawn(async move {
            fut.await;
            drop(permit);
        });
    }
}

/// Collect all upstream proxy server IPs from the tunnel's proxy map.
/// These IPs must be excluded from firewall redirection to prevent loops.
fn collect_proxy_server_ips(tunnel: &Tunnel) -> Vec<IpAddr> {
    let route = tunnel.route_snapshot();
    let proxies = &route.proxies;
    let mut ips = HashSet::new();

    for proxy in proxies.values() {
        let addr_str = proxy.addr();
        if addr_str.is_empty() {
            continue;
        }

        // Try parsing as ip:port directly
        if let Ok(sock) = addr_str.parse::<SocketAddr>() {
            ips.insert(sock.ip());
            continue;
        }

        // Try parsing as just an IP
        if let Ok(ip) = addr_str.parse::<IpAddr>() {
            ips.insert(ip);
            continue;
        }

        // Try DNS resolution for host:port
        if let Ok(resolved) = addr_str.to_socket_addrs() {
            for sock in resolved {
                ips.insert(sock.ip());
            }
        }
    }

    let result: Vec<IpAddr> = ips.into_iter().collect();
    info!(
        "Collected {} upstream proxy IPs for firewall bypass: {:?}",
        result.len(),
        result
    );
    result
}

async fn handle_tproxy_conn(
    tunnel: Tunnel,
    stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Recover the original destination address
    let orig_dst = orig_dest::get_original_dst(&stream, listen_addr)?;

    // Skip connections where original dest equals listen addr (self-connection)
    if orig_dst == listen_addr {
        return Err("original destination is the listen address (loop detected)".into());
    }

    handle_tproxy_flow(
        tunnel,
        stream,
        src_addr,
        orig_dst,
        listen_addr,
        sniffer,
        name,
    )
    .await
}

/// Everything after original-destination recovery, split out so tests can
/// drive the flow with a plain loopback socket (`SO_ORIGINAL_DST` /
/// `DIOCNATLOOK` only succeed on genuinely redirected connections).
async fn handle_tproxy_flow(
    tunnel: Tunnel,
    mut stream: tokio::net::TcpStream,
    src_addr: SocketAddr,
    orig_dst: SocketAddr,
    listen_addr: SocketAddr,
    sniffer: Option<Arc<SnifferRuntime>>,
    name: String,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Build initial metadata with IP-literal host for sniffer / DNS-snoop.
    let mut metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::TProxy,
        src_ip: Some(src_addr.ip()),
        src_port: src_addr.port(),
        dst_ip: Some(orig_dst.ip()),
        dst_port: orig_dst.port(),
        in_name: name.into(),
        in_port: listen_addr.port(),
        ..Default::default()
    };

    // Recover hostname:
    // 1. SnifferRuntime (TLS SNI or HTTP Host) — replaces the old enable_sni path
    // 2. Fall back to DNS snooping reverse lookup (IP → domain from recent DNS queries)
    if let Some(rt) = sniffer.as_deref() {
        rt.sniff(&stream, &mut metadata).await;
    }

    let mut hostname = metadata.sniff_host.clone();
    if hostname.is_empty() {
        if let Some(domain) = tunnel.resolver().reverse_lookup(orig_dst.ip()) {
            hostname = domain;
        }
    }

    // Prefer sniff_host for display but fall back to DNS-snooped hostname.
    metadata.host = hostname;

    debug!(
        "TProxy {} -> {} (host: {})",
        src_addr,
        orig_dst,
        if metadata.host.is_empty() {
            "<none>"
        } else {
            &metadata.host
        }
    );

    let inner = tunnel.inner();
    // Fake-IP → host rewrite / unmapped-fake-IP drop (issue #618). Runs
    // after the sniffer + snoop recovery above so a still-known host
    // rescues the flow instead of dropping it.
    if matches!(
        inner.pre_handle_metadata(&mut metadata),
        meow_tunnel::PreHandleVerdict::Drop
    ) {
        return Err("unmapped fake-ip destination".into());
    }
    // Strict `resolve_proxy` below requires the dst-IP pre-resolution
    // contract (match_engine doc): fake-IP rescue above may have cleared
    // `dst_ip` after recovering the hostname, and without this, IP rules
    // never matched on the TProxy TCP path at all (issue #625 review).
    inner.pre_resolve(&mut metadata).await;
    let admission = inner.tcp_admission();
    let Some(ResolvedTarget {
        adapter: proxy,
        rule_name,
        rule_payload,
        route,
    }) = inner.resolve_proxy(&metadata).await
    else {
        return Err("no matching rule".into());
    };
    // The registry pin is needed only until the dial resolves its chained
    // front hops — a long-lived relay must not pin the generation.
    let mut route = Some(route);

    info!(
        "{} --> {} match {}({}) using {}",
        metadata.source_address(),
        metadata.remote_address(),
        rule_name,
        rule_payload,
        proxy.name()
    );

    let Some(_guard) = admission.track_named(&metadata, rule_name, rule_payload, proxy.name())
    else {
        return Ok(());
    };

    // Relay buffers on the future's stack — zero per-relay heap allocation (ADR-0011 T6).
    let mut relay_buf_up = [0u8; RELAY_BUF_SIZE];
    let mut relay_buf_dn = [0u8; RELAY_BUF_SIZE];

    _guard
        .run_until_closed(async {
            let dial = with_dial_timeout(proxy.name(), proxy.dial_tcp(&metadata)).await;
            drop(route.take());
            match dial {
                Ok(mut remote) => {
                    let up = Arc::clone(_guard.counters());
                    let dn = Arc::clone(_guard.counters());
                    match copy_bidirectional_buf_tracked(
                        &mut stream,
                        &mut remote,
                        &mut relay_buf_up,
                        &mut relay_buf_dn,
                        |n| {
                            inner
                                .stats
                                .record_upload(&up, n as meow_common::atomic::Int);
                        },
                        |n| {
                            inner
                                .stats
                                .record_download(&dn, n as meow_common::atomic::Int);
                        },
                    )
                    .await
                    {
                        Ok((up, down)) => {
                            debug!("TProxy relay closed: up={up} down={down}");
                        }
                        Err(e) => debug!("TProxy relay error: {e}"),
                    }
                }
                Err(e) => warn!("TProxy dial error: {e}"),
            }
        })
        .await;
    // _guard drops here, removing the entry from Statistics.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;
    use tokio::sync::{mpsc, Notify};

    /// Regression test for issue #435: a `max_connections: N` cap must never
    /// let more than `N` handler futures run concurrently, even when far more
    /// than `N` clients connect at once.
    ///
    /// The handler blocks on a shared `Notify` until told to proceed, so the
    /// test can deterministically observe the in-flight count saturate at
    /// exactly `N` (rather than racing against real work durations).
    #[tokio::test]
    async fn accept_loop_never_exceeds_max_connections() {
        const CAP: usize = 3;
        const CLIENTS: usize = 10;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        // Signalled once `CAP` handlers are simultaneously in flight, so the
        // driver knows saturation was actually reached before releasing them.
        let saturated = Arc::new(Notify::new());

        let in_flight_h = Arc::clone(&in_flight);
        let max_observed_h = Arc::clone(&max_observed);
        let release_h = Arc::clone(&release);
        let saturated_h = Arc::clone(&saturated);

        let loop_task = tokio::spawn(async move {
            bounded_accept_loop(
                listener,
                CAP,
                "test-tproxy".to_string(),
                move |stream, _src| {
                    let in_flight = Arc::clone(&in_flight_h);
                    let max_observed = Arc::clone(&max_observed_h);
                    let release = Arc::clone(&release_h);
                    let saturated = Arc::clone(&saturated_h);
                    async move {
                        drop(stream);
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_observed.fetch_max(now, Ordering::SeqCst);
                        if now == CAP {
                            saturated.notify_one();
                        }
                        release.notified().await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    }
                },
            )
            .await
        });

        // Dial all clients up front; only CAP permits exist, so at most CAP
        // handlers can be in flight no matter how many connections arrive.
        let (done_tx, mut done_rx) = mpsc::channel::<()>(CLIENTS);
        for _ in 0..CLIENTS {
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let _ = TcpStream::connect(addr).await;
                let _ = done_tx.send(()).await;
            });
        }
        drop(done_tx);

        // Wait until the cap is actually saturated before asserting on it.
        tokio::time::timeout(Duration::from_secs(5), saturated.notified())
            .await
            .expect("cap was never saturated");
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            CAP,
            "in-flight count should sit exactly at the cap once saturated"
        );

        // Release handlers one at a time; the in-flight count must never
        // exceed CAP as the remaining queued clients get admitted.
        for _ in 0..CLIENTS {
            release.notify_one();
            tokio::time::sleep(Duration::from_millis(5)).await;
            assert!(
                in_flight.load(Ordering::SeqCst) <= CAP,
                "in-flight count exceeded the configured cap"
            );
        }

        // Drain remaining client-side completions (best-effort; some may
        // have failed to dial if the OS backlog was briefly full).
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..CLIENTS {
                done_rx.recv().await;
            }
        })
        .await;

        loop_task.abort();
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            CAP,
            "cap should have been reached but never exceeded"
        );
    }

    /// Regression test for the `max_connections == 0` sentinel: it must
    /// disable the cap entirely (no semaphore), letting far more handler
    /// futures run concurrently than any small numeric cap would allow.
    #[tokio::test]
    async fn accept_loop_unbounded_when_max_connections_is_zero() {
        // Deliberately larger than any small cap (e.g. the CAP=3 used by
        // `accept_loop_never_exceeds_max_connections`) so saturating this
        // many concurrent handlers proves `0` truly means unbounded rather
        // than merely "a bigger-than-3 limit".
        const CLIENTS: usize = 20;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let in_flight = Arc::new(AtomicUsize::new(0));
        let max_observed = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(Notify::new());
        // Signalled once all CLIENTS handlers are simultaneously in flight,
        // proving no cap ever throttled admission below that count.
        let all_in_flight = Arc::new(Notify::new());

        let in_flight_h = Arc::clone(&in_flight);
        let max_observed_h = Arc::clone(&max_observed);
        let release_h = Arc::clone(&release);
        let all_in_flight_h = Arc::clone(&all_in_flight);

        let loop_task = tokio::spawn(async move {
            bounded_accept_loop(
                listener,
                0, // unlimited sentinel
                "test-tproxy-unbounded".to_string(),
                move |stream, _src| {
                    let in_flight = Arc::clone(&in_flight_h);
                    let max_observed = Arc::clone(&max_observed_h);
                    let release = Arc::clone(&release_h);
                    let all_in_flight = Arc::clone(&all_in_flight_h);
                    async move {
                        drop(stream);
                        let now = in_flight.fetch_add(1, Ordering::SeqCst) + 1;
                        max_observed.fetch_max(now, Ordering::SeqCst);
                        if now == CLIENTS {
                            all_in_flight.notify_one();
                        }
                        release.notified().await;
                        in_flight.fetch_sub(1, Ordering::SeqCst);
                    }
                },
            )
            .await
        });

        let (done_tx, mut done_rx) = mpsc::channel::<()>(CLIENTS);
        for _ in 0..CLIENTS {
            let done_tx = done_tx.clone();
            tokio::spawn(async move {
                let _ = TcpStream::connect(addr).await;
                let _ = done_tx.send(()).await;
            });
        }
        drop(done_tx);

        // With no cap, all CLIENTS handlers must be able to run at once —
        // none should be blocked waiting for a permit.
        tokio::time::timeout(Duration::from_secs(5), all_in_flight.notified())
            .await
            .expect("all handlers should have been admitted concurrently with max_connections=0");
        assert_eq!(
            in_flight.load(Ordering::SeqCst),
            CLIENTS,
            "unbounded accept loop should admit every connection without queuing"
        );

        release.notify_waiters();
        let _ = tokio::time::timeout(Duration::from_secs(5), async {
            for _ in 0..CLIENTS {
                done_rx.recv().await;
            }
        })
        .await;

        loop_task.abort();
        assert_eq!(
            max_observed.load(Ordering::SeqCst),
            CLIENTS,
            "max_connections=0 must allow more concurrent handlers than any small cap"
        );
    }

    /// Issue #563: `firewall: false` delegates rule management to an
    /// external system — `run_on` must bind, accept, and stay up without
    /// invoking nftables/pfctl. The managed path needs privileges a test
    /// environment does not have, so this test pins the externally-managed
    /// contract: no early error return from `FirewallGuard::setup`, and
    /// client connects still reach the accept loop.
    ///
    /// Also pins the startup-log disclosure ("external firewall management")
    /// that the QEMU harness greps for (`tests/tproxy-qemu/guest-init.sh`).
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn run_on_external_firewall_accepts_without_setup() {
        #[derive(Clone)]
        struct Sink(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);
        impl std::io::Write for Sink {
            fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(buf);
                Ok(buf.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Sink {
            type Writer = Sink;
            fn make_writer(&'a self) -> Sink {
                self.clone()
            }
        }
        let sink = Sink(std::sync::Arc::new(std::sync::Mutex::new(Vec::new())));
        let subscriber = tracing_subscriber::fmt()
            .with_writer(sink.clone())
            .with_ansi(false)
            .with_max_level(tracing::Level::INFO)
            .finish();

        tracing::subscriber::with_default(subscriber, || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(async {
                    let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
                        vec![],
                        vec![],
                        meow_common::DnsMode::Normal,
                        meow_trie::DomainTrie::new(),
                        false,
                        true,
                    ));
                    let tunnel = meow_tunnel::Tunnel::new(resolver);

                    let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let addr = socket.local_addr().unwrap();

                    let listener =
                        TProxyListener::new(tunnel, addr, false, None, "ext-fw".to_string())
                            .with_firewall(false);
                    let mut task = tokio::spawn(listener.run_on(socket));

                    // A client connect must be accepted — the accept loop runs
                    // without any firewall tooling being invoked. The
                    // connection itself is then closed by the handler (no
                    // REDIRECT metadata to recover), which is irrelevant here.
                    tokio::time::timeout(Duration::from_secs(2), TcpStream::connect(addr))
                        .await
                        .expect("connect timed out")
                        .expect("connect failed");

                    // The listener must still be running — if firewall setup
                    // had been attempted it would have returned an error on
                    // this unprivileged host before the accept loop started.
                    // Waiting out the timeout means the task stayed alive;
                    // finishing means an early error return.
                    match tokio::time::timeout(Duration::from_secs(1), &mut task).await {
                        Err(_) => {}
                        Ok(res) => panic!("firewall: false listener exited early: {res:?}"),
                    }
                    task.abort();
                });
        });

        let logs = String::from_utf8_lossy(&sink.0.lock().unwrap()).into_owned();
        assert!(
            logs.contains("external firewall management"),
            "external mode must disclose itself in the startup log, got: {logs}"
        );
    }

    /// The inverse contract on platforms without orig-dest recovery:
    /// `firewall: false` must not smuggle a dead listener up — `run_on`
    /// refuses before accepting (issue #563).
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    #[tokio::test]
    async fn run_on_external_firewall_errors_on_unsupported_platform() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = meow_tunnel::Tunnel::new(resolver);

        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let listener = TProxyListener::new(tunnel, addr, false, None, "ext-fw".to_string())
            .with_firewall(false);
        let err = listener
            .run_on(socket)
            .await
            .expect_err("external management must refuse on this platform");
        // "is not supported" pins the early gate — the managed-mode setup
        // path would instead fail with "firewall not supported", which
        // lacks the "is" and would mean `firewall: false` was ignored.
        assert!(
            err.to_string().contains("is not supported"),
            "unexpected error: {err}"
        );
    }

    /// Issue #564: `udp: true` is Linux-only — on any other platform the
    /// listener must fail at startup, never silently degrade to TCP-only.
    /// The positive path (transparent socket + flow dispatch) is exercised
    /// by the QEMU suite, which requires a Linux guest.
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn run_on_udp_rejected_off_linux() {
        let resolver = std::sync::Arc::new(meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            false,
            true,
        ));
        let tunnel = meow_tunnel::Tunnel::new(resolver);

        let socket = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = socket.local_addr().unwrap();

        let listener = TProxyListener::new(tunnel, addr, false, None, "udp".to_string())
            .with_firewall(false)
            .with_udp(true, std::time::Duration::from_secs(60));
        let err = listener
            .run_on(socket)
            .await
            .expect_err("udp: true must fail off Linux");
        // macOS reaches the `udp` gate ("Linux-only"); Windows hits the
        // earlier platform gate for `firewall: false`. Either way the
        // listener must never silently degrade to TCP-only.
        let msg = err.to_string();
        assert!(
            msg.contains("Linux") || msg.contains("not supported on this platform"),
            "unexpected error: {err}"
        );
    }

    /// Issue #625 review: the strict `resolve_proxy` match requires the
    /// pre-resolve contract — a fake-IP-rescued flow arrives with
    /// `dst_ip=None` and a recovered host, so `pre_resolve` must run or the
    /// IP-CIDR slot can never match and the flow silently falls through to
    /// `MATCH`. Without the call, this test would observe `MATCH/DIRECT`.
    #[tokio::test]
    async fn tcp_flow_pre_resolves_dst_ip_for_ip_rules() {
        use meow_dns::fakeip::{MemoryStore, Pool};

        let mut resolver = meow_dns::Resolver::new(
            vec![],
            vec![],
            meow_common::DnsMode::FakeIp,
            meow_trie::DomainTrie::new(),
            true,
            true,
        );
        let net = "198.18.0.0/16".parse::<ipnet::IpNet>().unwrap();
        resolver.set_fakeip_v4(Arc::new(
            Pool::new(net, Arc::new(MemoryStore::new(1024))).unwrap(),
        ));
        let resolver = Arc::new(resolver);
        let fake = resolver.lookup_ipv4("example.test").await.unwrap();
        assert!(resolver.is_fake_ip(fake), "expected a fake IP, got {fake}");
        let real = IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));
        resolver.preload_cache("example.test", &[real], Duration::from_secs(300));

        let tunnel = Tunnel::new(resolver);
        let res = meow_config::rebuild_from_raw(&Default::default()).unwrap();
        tunnel.update_proxies(res.proxies, res.dialer_registry);
        tunnel.update_rules(vec![
            meow_rules::parse_rule("IP-CIDR,127.0.0.1/32,REJECT", &Default::default()).unwrap(),
            Box::new(meow_rules::final_rule::FinalRule::new("DIRECT")),
        ]);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let listen_addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(listen_addr).await.unwrap();
        let (server, peer) = listener.accept().await.unwrap();
        let orig_dst = SocketAddr::new(fake, 443);
        let stats = Arc::clone(tunnel.statistics());

        tokio::time::timeout(Duration::from_secs(5), async {
            let task = tokio::spawn(handle_tproxy_flow(
                tunnel,
                server,
                peer,
                orig_dst,
                listen_addr,
                None,
                "tproxy".into(),
            ));
            // The relay waits for client EOF — close our end so the flow
            // completes after the REJECT adapter yields its eof stream.
            drop(client);
            let _ = task.await.unwrap();
            let snap = stats.rule_match.snapshot();
            assert!(
                snap.contains(&(("IP-CIDR", "REJECT"), 1)),
                "pre_resolve must let the IP-CIDR rule match — got {snap:?}"
            );
        })
        .await
        .expect("pre_resolve must let the IP-CIDR rule match the rescued host");
    }

    #[test]
    fn default_max_connections_matches_mixed_listener_default() {
        // Kept as separate constants (see DEFAULT_MAX_CONNECTIONS doc comment)
        // but they must stay numerically in sync with the config default of
        // 256 (`meow_config`'s `raw.max_connections.unwrap_or(256)`).
        assert_eq!(DEFAULT_MAX_CONNECTIONS, 256);
    }
}
