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
/// Slack on the `t3 − t2 ≤ t4 − t1` bound. The server's processing
/// interval physically sits inside the exchange's round trip, so this
/// only covers timestamp quantization and coarse clocks — a gap beyond
/// it is a clock jump on the wire, not processing.
const SERVER_PROCESSING_SLACK_NS: i128 = 1_000_000_000;
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
    /// Serializes a worker's generation-check + offset-store against the
    /// supervisor's bump + clear — a superseded publish must not slip
    /// between the two and resurrect a cleared offset. Held only across
    /// the check+store pair, never across an `.await`.
    publish: Arc<Mutex<()>>,
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
            publish: Arc::new(Mutex::new(())),
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
        let gen = {
            let _publish = self.publish.lock().unwrap();
            let gen = self.generation.fetch_add(1, Ordering::AcqRel) + 1;
            // Any change — disable OR a new endpoint/interval/dialer —
            // clears the published offset: the outgoing worker's last
            // good sample belongs to a dead configuration and must not
            // keep bending protocol timestamps while its successor has
            // not sampled yet.
            meow_common::set_protocol_offset_ns(None);
            gen
        };
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
                Arc::clone(&self.publish),
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
        let _publish = self.publish.lock().unwrap();
        meow_common::set_protocol_offset_ns(None);
    }
}

impl Drop for NtpSupervisor {
    /// A dropped supervisor must not leak a forever-polling worker or
    /// leave its last offset bending protocol timestamps.
    fn drop(&mut self) {
        if let Some(task) = self.state.lock().unwrap().task.take() {
            task.abort();
        }
        let _publish = self.publish.lock().unwrap();
        meow_common::set_protocol_offset_ns(None);
    }
}

async fn run_worker(
    cfg: meow_config::NtpConfig,
    tunnel: Weak<meow_tunnel::TunnelInner>,
    generation: Arc<AtomicU64>,
    gen: u64,
    publish: Arc<Mutex<()>>,
) {
    let mut ticker =
        tokio::time::interval(Duration::from_secs(u64::from(cfg.interval_minutes) * 60));
    // Upstream's `time.Ticker` anchors to the start time and drops ticks
    // a stalled poll missed — `Skip` keeps that original cadence (a stall
    // does not permanently shift the phase; `Delay` would, `Burst` would
    // queue catch-ups upstream never runs).
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    // `interval` ticks once immediately — the immediate first exchange.
    loop {
        ticker.tick().await;
        for attempt in 1..=MAX_ATTEMPTS {
            match tokio::time::timeout(ATTEMPT_TIMEOUT, poll_once(&cfg, &tunnel)).await {
                Ok(Ok(offset_ns)) => {
                    // Fence: a worker superseded mid-exchange must not
                    // overwrite its successor's offset. The check and the
                    // store share `publish` with the supervisor's
                    // bump + clear, so a reconcile can't slip the clear
                    // between them and leave a stale offset published.
                    let _publish = publish.lock().unwrap();
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
    // Wrong peer — `src_matches` applies the same contract every UDP
    // demux uses: literal targets pin the canonical IP+port (a v4-mapped
    // reply source folds to plain v4); name-bound conns can only check
    // the dialed port, which they check unconditionally.
    if !target.src_matches(from) {
        return Err(format!("reply from wrong peer {from}"));
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
    // Mode 4 (server) only — a broadcast-mode (5) packet is not an
    // answer to our client request.
    if mode != 4 || vn == 0 || vn > 4 || stratum > 15 {
        return Err(format!(
            "invalid server mode {mode}/version {vn}/stratum {stratum}"
        ));
    }
    let t2_secs = u32::from_be_bytes(reply[32..36].try_into().unwrap());
    let t2_frac = u32::from_be_bytes(reply[36..40].try_into().unwrap());
    let t3_secs = u32::from_be_bytes(reply[40..44].try_into().unwrap());
    let t3_frac = u32::from_be_bytes(reply[44..48].try_into().unwrap());
    // Only the all-zero timestamp is the unsynchronized marker — zero
    // seconds with a nonzero fraction is a real (era-boundary) instant.
    if (t2_secs == 0 && t2_frac == 0) || (t3_secs == 0 && t3_frac == 0) {
        return Err("server returned a zero timestamp".into());
    }
    let t1 = t1_wall
        .duration_since(UNIX_EPOCH)
        .map_err(|e| e.to_string())?;
    let t4d = t4.duration_since(UNIX_EPOCH).map_err(|e| e.to_string())?;
    let t1_ns = t1.as_nanos() as i128;
    let t4_ns = t4d.as_nanos() as i128;
    let t2_ns = ntp_secs_to_unix_nanos(t2_secs, t2_frac, &t1_wall);
    let t3_ns = ntp_secs_to_unix_nanos(t3_secs, t3_frac, &t1_wall);
    // The server's own ordering must hold: it received before it sent,
    // so t3 >= t2. An inverted pair is not a plausible clock reading —
    // it is a forged or corrupted reply, and folding it into the offset
    // would let it pass at half magnitude.
    if t3_ns < t2_ns {
        return Err("server timestamps out of order (t3 < t2)".into());
    }
    // The request was in flight before t2 and the reply after t3, so the
    // server's own processing interval cannot exceed the round trip it
    // was measured inside — a larger gap is a clock jump or a replayed
    // packet, and folding it into the offset publishes the jump at half
    // magnitude (issue #974 review).
    if t3_ns - t2_ns > t4_ns - t1_ns + SERVER_PROCESSING_SLACK_NS {
        return Err("server processing gap exceeds the exchange RTT".into());
    }
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

    /// A syntactically valid mode-4 reply scaffolding for the validator
    /// tests below: originate echoing `tx`, stratum 1, caller-chosen
    /// server receive/transmit timestamps.
    fn reply_with(tx: &[u8; 8], t2: [u8; 8], t3: [u8; 8]) -> Vec<u8> {
        let mut r = vec![0u8; 48];
        r[0] = 0x24; // LI=0, VN=4, Mode=4
        r[1] = 1;
        r[24..32].copy_from_slice(tx);
        r[32..40].copy_from_slice(&t2);
        r[40..48].copy_from_slice(&t3);
        r
    }

    /// Server timestamps that run backwards (t3 < t2) are forged or
    /// corrupted — the reply is rejected rather than letting the pair
    /// fold into the offset at half magnitude.
    #[test]
    fn reply_validation_rejects_inverted_server_timestamps() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let reply = reply_with(
            &tx,
            ntp_timestamp(t1 + Duration::from_secs(60)),
            ntp_timestamp(t1 + Duration::from_secs(30)),
        );
        let target = UdpTarget::named("ntp.test", 123);
        let from: SocketAddr = "0.0.0.0:123".parse().unwrap();
        let e = validate_reply(&reply, &tx, t1, t1, &target, from).unwrap_err();
        assert!(e.contains("out of order"), "{e}");
    }

    /// The server's processing interval `t3 − t2` sits inside the
    /// measured round trip — a gap beyond `RTT + slack` is a clock jump
    /// on the wire, and publishing it would bend the offset by half the
    /// jump (issue #974 review).
    #[test]
    fn reply_validation_rejects_processing_gap_beyond_rtt() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let target = UdpTarget::named("ntp.test", 123);
        let from: SocketAddr = "0.0.0.0:123".parse().unwrap();

        // Instant reply (RTT = 0) but the server claims 5 s of
        // processing — impossible inside this exchange.
        let reply = reply_with(
            &tx,
            ntp_timestamp(t1),
            ntp_timestamp(t1 + Duration::from_secs(5)),
        );
        let e = validate_reply(&reply, &tx, t1, t1, &target, from).unwrap_err();
        assert!(e.contains("RTT"), "{e}");

        // The same 5 s gap is plausible inside a 10 s round trip.
        let reply = reply_with(
            &tx,
            ntp_timestamp(t1),
            ntp_timestamp(t1 + Duration::from_secs(5)),
        );
        assert!(
            validate_reply(&reply, &tx, t1, t1 + Duration::from_secs(10), &target, from).is_ok(),
            "a processing gap inside the measured RTT must pass"
        );
    }

    /// Mode 5 (broadcast) is not an answer to a client request — only
    /// mode 4 is a server reply.
    #[test]
    fn reply_validation_rejects_broadcast_mode() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let ts = ntp_timestamp(t1);
        let mut reply = reply_with(&tx, ts, ts);
        reply[0] = 0x25; // LI=0, VN=4, Mode=5 (broadcast)
        let target = UdpTarget::named("ntp.test", 123);
        let from: SocketAddr = "0.0.0.0:123".parse().unwrap();
        let e = validate_reply(&reply, &tx, t1, t1, &target, from).unwrap_err();
        assert!(e.contains("mode"), "{e}");
    }

    /// A name-bound conn whose read reports an unspecified source IP
    /// still has its port to check — the dialed port is the only locally
    /// known half of the wire identity.
    #[test]
    fn reply_validation_checks_source_port_when_ip_unspecified() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let ts = ntp_timestamp(t1);
        let reply = reply_with(&tx, ts, ts);
        let target = UdpTarget::named("ntp.test", 123);

        let wrong_port: SocketAddr = "0.0.0.0:999".parse().unwrap();
        assert!(
            validate_reply(&reply, &tx, t1, t1, &target, wrong_port).is_err(),
            "unspecified ip + wrong port must not slip the peer check"
        );
        let no_port: SocketAddr = "0.0.0.0:0".parse().unwrap();
        assert!(validate_reply(&reply, &tx, t1, t1, &target, no_port).is_err());
        let right_port: SocketAddr = "0.0.0.0:123".parse().unwrap();
        assert!(validate_reply(&reply, &tx, t1, t1, &target, right_port).is_ok());
    }

    /// Only the all-zero timestamp marks "unsynchronized" — zero seconds
    /// with a nonzero fraction is a real (era-boundary) instant and must
    /// not trip the zero check.
    #[test]
    fn reply_validation_zero_check_requires_all_zero_bits() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let target = UdpTarget::named("ntp.test", 123);
        let from: SocketAddr = "0.0.0.0:123".parse().unwrap();

        let mut half = [0u8; 8];
        half[4..8].copy_from_slice(&0x8000_0000u32.to_be_bytes());
        let reply = reply_with(&tx, half, half);
        let e = validate_reply(&reply, &tx, t1, t1, &target, from).unwrap_err();
        assert!(
            !e.contains("zero timestamp"),
            "sec=0/frac≠0 must not be the zero rejection: {e}"
        );

        let reply = reply_with(&tx, [0; 8], [0; 8]);
        assert!(validate_reply(&reply, &tx, t1, t1, &target, from)
            .unwrap_err()
            .contains("zero timestamp"));
    }

    /// `DirectDialer` canonicalizes `[::ffff:127.0.0.1]` to `127.0.0.1`
    /// before connecting — the socket reports the plain v4 source, and
    /// the peer check must fold both sides the same way.
    #[test]
    fn reply_validation_accepts_canonical_peer_equivalent() {
        let t1 = SystemTime::now();
        let tx = ntp_timestamp(t1);
        let ts = ntp_timestamp(t1);
        let reply = reply_with(&tx, ts, ts);
        let target = UdpTarget::Addr("[::ffff:127.0.0.1]:123".parse().unwrap());
        let from: SocketAddr = "127.0.0.1:123".parse().unwrap();
        assert!(
            validate_reply(&reply, &tx, t1, t1, &target, from).is_ok(),
            "v4-mapped target vs plain v4 reply source must compare canonically"
        );
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

    /// `set_protocol_offset_ns` is a process global — the supervisor
    /// tests below would clear/publish over each other under parallel
    /// `cargo test`, so they serialize through this gate.
    static PUBLISHED_OFFSET_GATE: StdMutex<()> = StdMutex::new(());

    fn offset_gate() -> std::sync::MutexGuard<'static, ()> {
        PUBLISHED_OFFSET_GATE
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn test_cfg(server: &str) -> meow_config::NtpConfig {
        meow_config::NtpConfig {
            enable: true,
            server: server.to_string(),
            port: 9,
            // A year between polls — the worker only ever runs its
            // immediate exchange (a UDP dial to the literal that never
            // answers inside the 5 s attempt bound).
            interval_minutes: 525_600,
            dialer_proxy: None,
        }
    }

    fn supervisor() -> NtpSupervisor {
        let resolver = Arc::new(meow_dns::Resolver::new(
            vec!["8.8.8.8:53".parse().unwrap()],
            vec![],
            meow_common::DnsMode::Normal,
            meow_trie::DomainTrie::new(),
            true,
            true,
        ));
        NtpSupervisor::new(&meow_tunnel::Tunnel::new(resolver))
    }

    /// Signed seconds `protocol_now()` currently reports ahead of wall
    /// time — ~3600 while an offset is published, ~0 once cleared.
    fn published_shift_secs() -> i64 {
        meow_common::protocol_now()
            .duration_since(SystemTime::now())
            .map_or_else(|e| -(e.duration().as_secs() as i64), |d| d.as_secs() as i64)
    }

    /// `dialer-proxy: DIRECT` and an omitted key resolve to the same
    /// effective config — reconcile sees no diff and keeps the running
    /// worker generation (issue #974 normalization).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_treats_direct_spelling_as_omitted() {
        let _gate = offset_gate();
        let sup = supervisor();
        let explicit = meow_config::resolve_ntp(
            &meow_config::parse_raw_yaml(
                "ntp:\n  enable: true\n  server: 127.0.0.1\n  port: 9\n  interval: 525600\n  dialer-proxy: DIRECT\n",
            )
            .unwrap(),
        )
        .unwrap();
        let omitted = meow_config::resolve_ntp(
            &meow_config::parse_raw_yaml(
                "ntp:\n  enable: true\n  server: 127.0.0.1\n  port: 9\n  interval: 525600\n",
            )
            .unwrap(),
        )
        .unwrap();
        assert_eq!(explicit, omitted);
        sup.reconcile(explicit);
        let gen = sup.generation.load(Ordering::Acquire);
        sup.reconcile(omitted);
        assert_eq!(
            sup.generation.load(Ordering::Acquire),
            gen,
            "an equal effective config must not bump the worker generation"
        );
        drop(_gate);
        sup.shutdown().await;
    }

    /// Reconcile clears the published offset on ANY config change — not
    /// only enabled→disabled — while an unchanged config leaves it
    /// (issue #974): the outgoing worker's last good sample belongs to a
    /// dead configuration.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reconcile_clears_offset_on_any_change() {
        let _gate = offset_gate();
        let sup = supervisor();
        let cfg_a = test_cfg("127.0.0.1");
        let cfg_b = test_cfg("127.0.0.2");
        let shift = Some(3_600_000_000_000); // +1 h

        sup.reconcile(cfg_a.clone());
        // An identical reconcile is a no-op — the offset a live worker
        // published stays published.
        meow_common::set_protocol_offset_ns(shift);
        sup.reconcile(cfg_a.clone());
        assert!(
            published_shift_secs() > 3_500,
            "unchanged reconcile must keep the published offset"
        );

        // enabled → enabled with a different endpoint clears it.
        sup.reconcile(cfg_b.clone());
        assert!(
            published_shift_secs() < 60,
            "a changed reconcile must clear the published offset"
        );

        // enabled → disabled clears it too.
        meow_common::set_protocol_offset_ns(shift);
        sup.reconcile(meow_config::NtpConfig {
            enable: false,
            ..cfg_b.clone()
        });
        assert!(
            published_shift_secs() < 60,
            "disable must clear the published offset"
        );
        // The std gate must release before any `.await` — the offset
        // assertions are done, shutdown is plain cleanup.
        drop(_gate);
        sup.shutdown().await;
    }

    /// A dropped supervisor aborts its worker and clears the offset —
    /// no forever-polling task, no stale correction (issue #974).
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn drop_aborts_worker_and_clears_offset() {
        let _gate = offset_gate();
        let sup = supervisor();
        sup.reconcile(test_cfg("127.0.0.1"));
        assert!(
            sup.state.lock().unwrap().task.is_some(),
            "enabled reconcile must spawn the worker"
        );
        meow_common::set_protocol_offset_ns(Some(3_600_000_000_000));
        drop(sup);
        assert!(
            published_shift_secs() < 60,
            "drop must clear the published offset"
        );
    }
}
