//! The `ntp:` service — bounded SNTP polls feeding
//! [`meow_common::protocol_now`] (issue #974).
//!
//! One worker per effective configuration: an immediate exchange at
//! start, then one per `interval` minutes with missed ticks skipped.
//! Each poll is at most three attempts, each bounded to five seconds
//! including resolution and dial; failures rate-limit their warnings,
//! keep the worker's last good offset, and never fail startup or a
//! commit. `write-to-system` does not exist here — the offset only ever
//! reaches `meow_common::set_protocol_offset_ns`.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use meow_proxy::dialer::{DirectDialer, ProxyDialer, TcpDialer, UdpTarget};
use tokio::task::JoinHandle;
use tracing::{info, warn};

/// Per-attempt bound — resolution and dial included — and the poll's
/// attempt ceiling (upstream's `loopUpdate` shape).
const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_ATTEMPTS: usize = 3;
/// Offsets beyond ±24 h are rejected before publishing — a wild sample
/// must never bend protocol timestamps.
const MAX_OFFSET_NS: i128 = 24 * 3600 * 1_000_000_000i128;
/// NTP's 1900 epoch offset from the Unix epoch.
const NTP_UNIX_EPOCH_DIFF_SECS: i64 = 2_208_988_800;

/// Owns the worker and the offset it publishes. Startup creates one
/// against the tunnel's weak inner; the API commit lane reconciles it
/// with each committed document; shutdown joins it. The worker holds a
/// `Weak` back at the tunnel, so a dying supervisor never keeps its
/// owner (or the route table) alive.
pub struct NtpSupervisor {
    tunnel: Weak<meow_tunnel::TunnelInner>,
    state: Mutex<WorkerState>,
    /// Worker generation — bumped on every reconcile so a stale worker's
    /// late exchange can never publish over a successor's offset.
    generation: Arc<AtomicU64>,
}

struct WorkerState {
    config: Option<meow_config::NtpConfig>,
    task: Option<JoinHandle<()>>,
}

impl NtpSupervisor {
    pub fn new(tunnel: &meow_tunnel::Tunnel) -> Self {
        Self {
            tunnel: tunnel.weak_inner(),
            state: Mutex::new(WorkerState {
                config: None,
                task: None,
            }),
            generation: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Swap the effective configuration. `enable: false` (or a changed
    /// endpoint/interval/dialer) cancels the worker and clears the
    /// published offset; an identical config is a no-op so a PUT that
    /// didn't touch `ntp:` never restarts the schedule.
    pub fn reconcile(&self, cfg: meow_config::NtpConfig) {
        let next = cfg.enable.then_some(cfg);
        let mut st = self.state.lock().unwrap();
        if st.config == next {
            return;
        }
        if let Some(task) = st.task.take() {
            task.abort();
        }
        let gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
        if st.config.is_some() && next.is_none() {
            // Disable clears the offset — a dead worker must not leave a
            // stale correction bending protocol timestamps.
            meow_common::set_protocol_offset_ns(None);
        }
        st.task = next.clone().map(|cfg| {
            info!(
                server = %cfg.server,
                port = cfg.port,
                interval = cfg.interval_minutes,
                dialer_proxy = cfg.dialer_proxy.as_deref().unwrap_or("direct"),
                "ntp: starting sync worker"
            );
            tokio::spawn(run_worker(
                cfg,
                Weak::clone(&self.tunnel),
                Arc::clone(&self.generation),
                gen,
            ))
        });
        st.config = next;
    }

    /// Cancel and join the worker — it must not outlive the supervisor.
    pub async fn shutdown(&self) {
        let task = self.state.lock().unwrap().task.take();
        if let Some(task) = task {
            task.abort();
            let _ = task.await;
        }
        meow_common::set_protocol_offset_ns(None);
    }
}

async fn run_worker(
    cfg: meow_config::NtpConfig,
    tunnel: Weak<meow_tunnel::TunnelInner>,
    generation: Arc<AtomicU64>,
    gen: u64,
) {
    let mut ticker =
        tokio::time::interval(Duration::from_secs(u64::from(cfg.interval_minutes) * 60));
    // Skip missed ticks rather than bursting after a pause — same policy
    // the provider refresh supervisors use.
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    // `interval` ticks once immediately — the immediate first exchange.
    loop {
        ticker.tick().await;
        for attempt in 1..=MAX_ATTEMPTS {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, poll_once(&cfg, &tunnel)).await {
                Ok(Ok(offset_ns)) => {
                    // Fence: a worker superseded mid-exchange must not
                    // overwrite its successor's offset.
                    if generation.load(Ordering::Acquire) != gen {
                        return;
                    }
                    meow_common::set_protocol_offset_ns(Some(offset_ns));
                    break;
                }
                Ok(Err(e)) => {
                    if attempt == MAX_ATTEMPTS {
                        warn!(
                            error = %e,
                            "ntp: poll failed after {MAX_ATTEMPTS} attempts; keeping last offset"
                        );
                    }
                }
                Err(_) => {
                    if attempt == MAX_ATTEMPTS {
                        warn!("ntp: poll timed out after {MAX_ATTEMPTS} attempts; keeping last offset");
                    }
                }
            }
        }
    }
}

/// One bounded exchange: dial, request, validate, compute the offset.
/// Returns the offset in nanoseconds (`server - local`).
async fn poll_once(
    cfg: &meow_config::NtpConfig,
    tunnel: &Weak<meow_tunnel::TunnelInner>,
) -> std::io::Result<i64> {
    let target = UdpTarget::named(&cfg.server, cfg.port);
    let conn = match cfg.dialer_proxy.as_deref() {
        None | Some("DIRECT") => DirectDialer.dial_udp_conn(target.clone(), true).await?,
        Some(name) => {
            // The live route choice is authoritative at dial time; the
            // snapshot pin is held until I/O completes so the front hop's
            // registry cell stays reachable (issue #974, same contract as
            // every named-frame dial).
            let inner = tunnel
                .upgrade()
                .ok_or_else(|| std::io::Error::other("tunnel gone"))?;
            let route = inner.route();
            let proxy = route.proxies.get(name).cloned().ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::NotFound,
                    format!("ntp.dialer-proxy '{name}' is no longer in the route table"),
                )
            })?;
            let conn = ProxyDialer::new(proxy)
                .dial_udp_conn(target.clone(), true)
                .await
                .map_err(|e| {
                    std::io::Error::new(
                        e.kind(),
                        format!(
                            "ntp.dialer-proxy '{name}' cannot carry UDP to the NTP server \
                             ({e}) — point at a UDP-capable front or use a literal server \
                             with direct egress"
                        ),
                    )
                })?;
            let (offset, result) = exchange(&*conn, &target).await;
            drop(route);
            return result.map(|_| offset);
        }
    };
    let (offset, result) = exchange(&*conn, &target).await;
    result.map(|_| offset)
}

/// Run one request/reply on `conn`. Returns `(offset_ns, result)` — the
/// pair shape lets callers drop their route pin after I/O completes
/// regardless of outcome.
async fn exchange(
    conn: &dyn meow_common::ProxyPacketConn,
    target: &UdpTarget,
) -> (i64, std::io::Result<i64>) {
    let t1_wall = SystemTime::now();
    let t1_mono = Instant::now();
    let mut req = [0u8; 48];
    req[0] = 0x23; // LI=0, VN=4, Mode=3 (client)
    let transmit = ntp_timestamp(t1_wall);
    req[40..48].copy_from_slice(&transmit);

    if let Err(e) = conn.write_packet(&req, &target.write_dst()).await {
        return (0, Err(std::io::Error::other(e)));
    }
    let mut buf = [0u8; 512];
    let (n, from) = match conn.read_packet(&mut buf).await {
        Ok(v) => v,
        Err(e) => return (0, Err(std::io::Error::other(e))),
    };
    let t4 = t1_wall + t1_mono.elapsed();
    let offset = validate_reply(&buf[..n], &transmit, t1_wall, t4, target, from)
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e));
    match offset {
        Ok(o) => (o, Ok(o)),
        Err(e) => (0, Err(e)),
    }
}

/// NTP's 64-bit fixed-point timestamp for a Unix `SystemTime`.
fn ntp_timestamp(t: SystemTime) -> [u8; 8] {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
    let secs = d.as_secs() + NTP_UNIX_EPOCH_DIFF_SECS as u64;
    let frac = ((d.subsec_nanos() as u64) << 32) / 1_000_000_000;
    let mut out = [0u8; 8];
    out[..4].copy_from_slice(&(secs as u32).to_be_bytes());
    out[4..].copy_from_slice(&(frac as u32).to_be_bytes());
    out
}

/// Seconds since the NTP epoch for an era-unfolded u32 timestamp, using
/// local wall time to pick the era — the standard wraparound rule.
fn ntp_secs_to_unix_nanos(sec: u32, frac: u32, approx: &SystemTime) -> i128 {
    let now1900 = approx
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs() as i64
        + NTP_UNIX_EPOCH_DIFF_SECS;
    let mut cand = (now1900 & !0xFFFF_FFFFi64) | i64::from(sec);
    if cand > now1900 + 0x8000_0000i64 {
        cand -= 1i64 << 32;
    } else if cand < now1900 - 0x8000_0000i64 {
        cand += 1i64 << 32;
    }
    (cand - NTP_UNIX_EPOCH_DIFF_SECS) as i128 * 1_000_000_000i128
        + ((u64::from(frac) * 1_000_000_000u64) >> 32) as i128
}

/// Parse and validate a reply, returning `offset_ns = ((t2−t1)+(t3−t4))/2`.
fn validate_reply(
    reply: &[u8],
    transmit_ts: &[u8; 8],
    t1_wall: SystemTime,
    t4: SystemTime,
    target: &UdpTarget,
    from: SocketAddr,
) -> Result<i64, String> {
    if reply.len() < 48 {
        return Err(format!("short NTP reply ({} bytes)", reply.len()));
    }
    // Wrong peer: literal targets pin IP+port; name-bound conns may
    // report the bound remote or an unspecified source — only a
    // specified source that mismatches the port is evidence.
    match target {
        UdpTarget::Addr(addr) => {
            if from != *addr {
                return Err(format!("reply from wrong peer {from}"));
            }
        }
        UdpTarget::Name { port, .. } => {
            if !from.ip().is_unspecified() && from.port() != *port {
                return Err(format!("reply from wrong peer {from}"));
            }
        }
    }
    if reply[24..32] != transmit_ts[..] {
        return Err("originate timestamp does not match request".into());
    }
    let li = reply[0] >> 6;
    let vn = (reply[0] >> 3) & 0x7;
    let mode = reply[0] & 0x7;
    let stratum = reply[1];
    if li == 3 {
        return Err("server clock unsynchronized (LI=3)".into());
    }
    if stratum == 0 {
        let kod = String::from_utf8_lossy(&reply[12..16]);
        return Err(format!("kiss-of-death reply (ref '{kod}')"));
    }
    if !(4..=5).contains(&mode) || vn == 0 || vn > 4 || stratum > 15 {
        return Err(format!(
            "invalid server mode {mode}/version {vn}/stratum {stratum}"
        ));
    }
    let t2_secs = u32::from_be_bytes(reply[32..36].try_into().unwrap());
    let t3_secs = u32::from_be_bytes(reply[40..44].try_into().unwrap());
    if t2_secs == 0 || t3_secs == 0 {
        return Err("server returned a zero timestamp".into());
    }
    let t1 = t1_wall
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let t4d = t4.duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
    let t1_ns = t1.as_nanos() as i128;
    let t4_ns = t4d.as_nanos() as i128;
    let t2_ns = ntp_secs_to_unix_nanos(
        t2_secs,
        u32::from_be_bytes(reply[36..40].try_into().unwrap()),
        &t1_wall,
    );
    let t3_ns = ntp_secs_to_unix_nanos(
        t3_secs,
        u32::from_be_bytes(reply[44..48].try_into().unwrap()),
        &t1_wall,
    );
    let offset = ((t2_ns - t1_ns) + (t3_ns - t4_ns)) / 2;
    if offset.abs() > MAX_OFFSET_NS {
        return Err("offset beyond the ±24 h cap".into());
    }
    i64::try_from(offset).map_err(|_| "offset overflows i64 ns".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// A `ProxyPacketConn` that plays an NTP server: `read_packet`
    /// answers the captured request with a syntactically valid reply
    /// whose transmit timestamp is `shift` nanoseconds ahead of the
    /// local clock — loopback-only, no sockets (issue #974).
    struct ScriptedConn {
        request: StdMutex<Vec<u8>>,
        shift_ns: i64,
        from: SocketAddr,
        /// Replies to hand out before the valid one (error cases).
        scripted: StdMutex<Vec<Vec<u8>>>,
    }

    impl ScriptedConn {
        fn new(shift_ns: i64) -> Self {
            Self {
                request: StdMutex::new(Vec::new()),
                shift_ns,
                from: "0.0.0.0:123".parse().unwrap(),
                scripted: StdMutex::new(Vec::new()),
            }
        }

        fn reply(&self, req: &[u8]) -> Vec<u8> {
            let mut r = vec![0u8; 48];
            r[0] = 0x24; // LI=0, VN=4, Mode=4 (server)
            r[1] = 1; // stratum 1
            r[24..32].copy_from_slice(&req[40..48]); // originate = our transmit
            let t = SystemTime::now()
                .checked_add(if self.shift_ns >= 0 {
                    Duration::from_nanos(self.shift_ns as u64)
                } else {
                    Duration::ZERO
                })
                .and_then(|t| {
                    if self.shift_ns < 0 {
                        t.checked_sub(Duration::from_nanos((-self.shift_ns) as u64))
                    } else {
                        Some(t)
                    }
                })
                .unwrap_or_else(SystemTime::now);
            let ts = ntp_timestamp(t);
            r[32..40].copy_from_slice(&ts); // t2
            r[40..48].copy_from_slice(&ts); // t3
            r
        }
    }

    #[async_trait::async_trait]
    impl meow_common::ProxyPacketConn for ScriptedConn {
        async fn read_packet(&self, buf: &mut [u8]) -> meow_common::Result<(usize, SocketAddr)> {
            let req = self.request.lock().unwrap().clone();
            let reply = self
                .scripted
                .lock()
                .unwrap()
                .pop()
                .unwrap_or_else(|| self.reply(&req));
            let n = reply.len().min(buf.len());
            buf[..n].copy_from_slice(&reply[..n]);
            Ok((n, self.from))
        }
        async fn write_packet(&self, buf: &[u8], _addr: &SocketAddr) -> meow_common::Result<usize> {
            *self.request.lock().unwrap() = buf.to_vec();
            Ok(buf.len())
        }
        fn local_addr(&self) -> meow_common::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().unwrap())
        }
        fn close(&self) -> meow_common::Result<()> {
            Ok(())
        }
    }

    /// Valid exchange: the computed offset tracks the server's shift
    /// within a generous jitter bound.
    #[tokio::test]
    async fn exchange_recovers_server_offset() {
        let conn = ScriptedConn::new(2_000_000_000); // +2 s
        let target = UdpTarget::named("ntp.test", 123);
        let (_, result) = exchange(&conn, &target).await;
        let offset = result.unwrap();
        // Offset ≈ +2 s; RTT is ~0 on the scripted conn, so ±500 ms is
        // far tighter than any failure mode we assert on.
        assert!(
            (offset - 2_000_000_000).abs() < 500_000_000,
            "offset {offset} not near +2 s"
        );
    }

    /// A reply beyond the ±24 h cap is rejected before publish.
    #[tokio::test]
    async fn exchange_rejects_beyond_cap() {
        let conn = ScriptedConn::new(25 * 3600 * 1_000_000_000); // +25 h
        let target = UdpTarget::named("ntp.test", 123);
        let (_, result) = exchange(&conn, &target).await;
        let e = result.unwrap_err().to_string();
        assert!(e.contains("24"), "expected the cap error, got: {e}");
    }

    /// Kiss-of-death / wrong originate / short / LI=3 replies are all
    /// rejected by `validate_reply`.
    #[test]
    fn reply_validation_rejects_malformed() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let target = UdpTarget::named("ntp.test", 123);
        let from: SocketAddr = "0.0.0.0:123".parse().unwrap();

        let short = [0u8; 10];
        assert!(validate_reply(&short, &tx, t1, t1, &target, from).is_err());

        let mut kod = vec![0u8; 48];
        kod[1] = 0; // stratum 0 — originate must match to reach this check
        kod[24..32].copy_from_slice(&tx);
        assert!(validate_reply(&kod, &tx, t1, t1, &target, from)
            .unwrap_err()
            .contains("kiss-of-death"));

        let mut bad_orig = vec![0u8; 48];
        bad_orig[0] = 0x24;
        bad_orig[1] = 1;
        bad_orig[24..32].copy_from_slice(&[0xff; 8]);
        assert!(validate_reply(&bad_orig, &tx, t1, t1, &target, from)
            .unwrap_err()
            .contains("originate"));

        let mut li3 = vec![0u8; 48];
        li3[0] = 0xC0 | 0x24;
        li3[1] = 1;
        li3[24..32].copy_from_slice(&tx);
        assert!(validate_reply(&li3, &tx, t1, t1, &target, from)
            .unwrap_err()
            .contains("LI=3"));

        // Wrong peer port on a name-bound target is evidence.
        let mut ok = vec![0u8; 48];
        ok[0] = 0x24;
        ok[1] = 1;
        ok[24..32].copy_from_slice(&tx);
        let ts = ntp_timestamp(t1);
        ok[32..40].copy_from_slice(&ts);
        ok[40..48].copy_from_slice(&ts);
        assert!(validate_reply(&ok, &tx, t1, t1, &target, from).is_ok());
        let wrong: SocketAddr = "9.9.9.9:999".parse().unwrap();
        assert!(validate_reply(&ok, &tx, t1, t1, &target, wrong).is_err());
    }

    /// Era unfold: a seconds value near `now` lands in the same era.
    #[test]
    fn era_unfold_picks_nearest() {
        let now = SystemTime::now();
        let d = now.duration_since(UNIX_EPOCH).unwrap();
        let ntp_sec = ((d.as_secs() + NTP_UNIX_EPOCH_DIFF_SECS as u64) & 0xFFFF_FFFF) as u32;
        let ns = ntp_secs_to_unix_nanos(ntp_sec, 0, &now);
        let unix_ns = d.as_nanos() as i128;
        assert!((ns - unix_ns).abs() < 2_000_000_000, "ns {ns} vs {unix_ns}");
    }
}
