mod bench_binary_size;
mod bench_connrate;
mod bench_dns;
mod bench_idle_conns;
mod bench_latency;
mod bench_memleak;
mod bench_memory;
mod bench_reload;
mod bench_throughput;
mod echo_server;
mod results;
mod socks5_client;

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use clap::Parser;

use results::{BenchmarkResults, ComparisonReport};

#[derive(Parser)]
#[command(name = "meow-bench", about = "Benchmark meow-rs vs Go mihomo")]
struct Args {
    /// Path to the Rust meow-rs binary
    #[arg(long, default_value = "target/release/meow")]
    rust_binary: PathBuf,

    /// CLI flag the binary takes before the config path (meow: -f, xray: -c)
    #[arg(long, default_value = "-f")]
    binary_arg: String,

    /// Path to the Go mihomo binary (skip Go benchmarks if absent)
    #[arg(long)]
    go_binary: Option<PathBuf>,

    /// Benchmark config file (SOCKS5 workloads W1–W3)
    #[arg(long, default_value = "config-bench.yaml")]
    config: PathBuf,

    /// DNS benchmark config file (W4); if absent, DNS bench is skipped
    #[arg(long)]
    dns_config: Option<PathBuf>,

    /// UDP port that the DNS bench config listens on
    #[arg(long, default_value = "15353")]
    dns_port: u16,

    /// JSON output file (stdout if omitted)
    #[arg(long)]
    output: Option<PathBuf>,

    /// Print markdown comparison table
    #[arg(long)]
    markdown: bool,

    /// Duration for sustained benchmarks in seconds
    #[arg(long, default_value = "10")]
    duration: u64,

    /// Number of latency iterations
    #[arg(long, default_value = "1000")]
    latency_iterations: usize,

    /// Concurrency for connection-rate test
    #[arg(long, default_value = "64")]
    concurrency: usize,

    /// Run only a specific benchmark (throughput, latency, connrate, dns,
    /// memleak, reload, idle, steady, proxied)
    #[arg(long)]
    only: Option<String>,

    /// Config that routes through a real outbound adapter (e.g. VLESS →
    /// sing-box); requires --singbox-binary. Adds the `proxied` workload:
    /// W1–W3 run against this config instead of the direct one.
    #[arg(long)]
    proxy_config: Option<PathBuf>,

    /// sing-box binary used as the proxied workload's server half
    /// (VLESS inbound → direct outbound, generated in-process)
    #[arg(long)]
    singbox_binary: Option<PathBuf>,

    /// Config for the `reload` workload — must enable `external-controller`
    /// on --api-port, bind `mixed-port` 17890, and carry the
    /// `DST-PORT,17895,bench-direct` probe rule (see
    /// config-bench-reload.yaml)
    #[arg(long, default_value = "config-bench-reload.yaml")]
    reload_config: PathBuf,

    /// REST API port the reload config's external-controller binds
    #[arg(long, default_value = "17892")]
    api_port: u16,

    /// PUT /configs count spread across the reload workload's load window
    #[arg(long, default_value = "10")]
    reloads: usize,

    /// Idle-connection count for the `idle` workload (ADR-0011 M-idle)
    #[arg(long, default_value = "10000")]
    idle_conns: usize,

    /// Hold window for the `idle` workload in seconds
    #[arg(long, default_value = "30")]
    idle_hold_secs: u64,

    /// Config for the memleak test (separate from the perf-bench config,
    /// because it needs a live proxy with internet access, e.g. ECH-TLS-tunnel)
    #[arg(long, default_value = "config.yaml")]
    memleak_config: PathBuf,

    /// Number of rounds for the memleak test
    #[arg(long, default_value = "10")]
    memleak_rounds: usize,

    /// Connections per round in the memleak test
    #[arg(long, default_value = "200")]
    memleak_conns: usize,

    /// SOCKS5 port the memleak config listens on (must match the config's mixed-port)
    #[arg(long, default_value = "17890")]
    memleak_port: u16,
}

const PROXY_PORT: u16 = 17890;

/// Proxied workload (#558): the sing-box VLESS server half listens on this
/// port; `config-bench-vless.yaml` dials it.  Loopback-only, spawned for
/// the duration of the proxied runs.
const VLESS_SERVER_PORT: u16 = 17893;
/// Must match `uuid:` in config-bench-vless.yaml.
const VLESS_SERVER_UUID: &str = "9b2e0d8a-0000-4000-8000-00000000b1e5";

/// Spawn `sing-box run` with a generated VLESS inbound (direct outbound).
/// Returns the child + the tempdir holding the config — keep both alive
/// for the duration of the proxied benchmarks.
fn start_singbox_server(bin: &Path) -> anyhow::Result<(std::process::Child, tempfile::TempDir)> {
    let dir = tempfile::tempdir()?;
    let config = format!(
        r#"{{
  "log": {{"level": "warn"}},
  "inbounds": [{{
    "type": "vless",
    "tag": "vless-in",
    "listen": "127.0.0.1",
    "listen_port": {VLESS_SERVER_PORT},
    "users": [{{"name": "bench", "uuid": "{VLESS_SERVER_UUID}"}}]
  }}],
  "outbounds": [{{"type": "direct", "tag": "out"}}]
}}"#
    );
    let config_path = dir.path().join("singbox.json");
    std::fs::write(&config_path, config)?;
    let child = Command::new(bin)
        .arg("run")
        .arg("-c")
        .arg(&config_path)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start sing-box at {}: {e}", bin.display()))?;
    Ok((child, dir))
}

/// Best-effort provenance for the JSON artifact — every field degrades
/// to `None` rather than failing the run.
fn collect_meta(args: &Args) -> results::BenchMeta {
    fn cmd_output(cmd: &str, args: &[&str]) -> Option<String> {
        let out = Command::new(cmd).args(args).output().ok()?;
        if !out.status.success() {
            return None;
        }
        let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
        (!s.is_empty()).then_some(s)
    }
    results::BenchMeta {
        meow_version: env!("CARGO_PKG_VERSION").to_string(),
        tested_version: args
            .rust_binary
            .to_str()
            .and_then(|b| cmd_output(b, &["-v"])),
        git_sha: cmd_output("git", &["rev-parse", "HEAD"]),
        rustc: cmd_output("rustc", &["--version"]),
        mihomo_version: std::env::var("MIHOMO_VERSION")
            .ok()
            .filter(|s| !s.is_empty()),
        platform: format!("{}-{}", std::env::consts::OS, std::env::consts::ARCH),
        duration_secs: args.duration,
    }
}

/// One connect attempt inside `wait_for_port*` — bounded so a filtered
/// or black-holed address cannot overshoot the outer deadline.
async fn probe_tcp(addr: SocketAddr) -> bool {
    tokio::time::timeout(
        Duration::from_millis(500),
        tokio::net::TcpStream::connect(addr),
    )
    .await
    .is_ok_and(|r| r.is_ok())
}

/// Port-readiness wait that also fails fast when the child already
/// exited — otherwise a config-rejected spawn reports "timeout waiting"
/// after the full deadline instead of "exited early" on the first poll.
async fn wait_for_port_guarded(
    addr: SocketAddr,
    timeout: Duration,
    child: &mut ChildGuard,
    what: &str,
) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        child.ensure_alive(what)?;
        if probe_tcp(addr).await {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for {addr} to become reachable");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Raise this process's `RLIMIT_NOFILE` soft limit toward the hard
/// limit.  The macOS default of 256 starves conn-heavy workloads long
/// before any real limit — BOTH sides pay per conn: the harness holds
/// the client socket and the spawned proxy holds inbound + outbound
/// (rlimits are inherited across exec, so children get it free).
#[cfg(unix)]
fn raise_nofile_limit() {
    unsafe {
        let mut lim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        if libc::getrlimit(libc::RLIMIT_NOFILE, &mut lim) == 0 {
            let target = lim.rlim_max.min(65_536);
            if lim.rlim_cur < target {
                lim.rlim_cur = target;
                if libc::setrlimit(libc::RLIMIT_NOFILE, &lim) != 0 {
                    eprintln!(
                        "[warn] setrlimit(RLIMIT_NOFILE, {target}) failed ({}) — conn-heavy legs may hit the low cap",
                        std::io::Error::last_os_error()
                    );
                } else {
                    // XNU can *silently clamp* rlim_cur to
                    // kern.maxfilesperproc and still return 0 — re-read
                    // to confirm the raise actually landed.
                    let mut after = libc::rlimit {
                        rlim_cur: 0,
                        rlim_max: 0,
                    };
                    if libc::getrlimit(libc::RLIMIT_NOFILE, &mut after) == 0
                        && after.rlim_cur < target
                    {
                        eprintln!(
                            "[warn] RLIMIT_NOFILE clamped to {} (wanted {target}) — conn-heavy legs may hit the low cap",
                            after.rlim_cur
                        );
                    }
                }
            }
        } else {
            eprintln!(
                "[warn] getrlimit(RLIMIT_NOFILE) failed ({}) — conn-heavy legs may hit the low cap",
                std::io::Error::last_os_error()
            );
        }
    }
}

/// Fail fast when a stale process squats the port a spawned child is
/// about to bind — `wait_for_port` alone cannot tell our listener from
/// a squatter's, and meow tolerates a `listeners:` bind failure
/// (the child stays alive serving nothing).
fn ensure_port_free(addr: SocketAddr, what: &str) -> anyhow::Result<()> {
    match std::net::TcpListener::bind(addr) {
        Ok(listener) => {
            drop(listener);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("{what}: {addr} already bound ({e}) — stale process squats the port")
        }
    }
}

/// UDP variant of `ensure_port_free` — the DNS leg's probe would
/// otherwise happily measure a stale DNS responder still holding the
/// port (any datagram answer looks "ready").
fn ensure_udp_port_free(addr: SocketAddr, what: &str) -> anyhow::Result<()> {
    match std::net::UdpSocket::bind(addr) {
        Ok(sock) => {
            drop(sock);
            Ok(())
        }
        Err(e) => {
            anyhow::bail!("{what}: {addr}/udp already bound ({e}) — stale process squats the port")
        }
    }
}

/// Spawn the proxy under test with bench-standard stdio (quiet stdout,
/// inherited stderr so config rejection is never silent).
fn spawn_meow(
    binary: &Path,
    binary_arg: &str,
    config: &Path,
) -> anyhow::Result<std::process::Child> {
    Command::new(binary)
        .arg(binary_arg)
        .arg(config.as_os_str())
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .map_err(|e| anyhow::anyhow!("failed to start {}: {e}", binary.display()))
}

async fn wait_for_udp_port_guarded(
    addr: SocketAddr,
    timeout: Duration,
    child: &mut ChildGuard,
    what: &str,
) -> anyhow::Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::{BinDecodable, BinEncodable};
    use tokio::net::UdpSocket;

    let deadline = tokio::time::Instant::now() + timeout;
    let sock = UdpSocket::bind("127.0.0.1:0").await?;

    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;
    // `.bench` is outside mihomo's default fake-ip-filter, so a fake-ip
    // config answers this probe locally instead of forwarding upstream.
    let name: Name = "probe.bench.".parse()?;
    msg.add_query(Query::query(name, RecordType::A));
    let probe = msg.to_bytes()?;

    loop {
        // Fail fast on a config-rejected child instead of spinning the
        // full deadline — same contract as `wait_for_port_guarded`.
        child.ensure_alive(what)?;
        let _ = sock.send_to(&probe, addr).await;
        let mut buf = [0u8; 512];
        // Ready only when the answer parses as a DNS *response* — any
        // datagram (or a recv io error) is not a readiness signal.
        if let Ok(Ok((n, _))) =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await
        {
            if Message::from_bytes(&buf[..n]).is_ok_and(|m| m.message_type == MessageType::Response)
            {
                return Ok(());
            }
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for DNS port {addr} to become reachable");
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

/// Grace period granted to a child between SIGTERM and the fallback
/// SIGKILL (Unix only; Windows terminates the child directly).
#[cfg_attr(not(unix), allow(dead_code))]
const SHUTDOWN_GRACE: Duration = Duration::from_secs(5);

/// Stops a benchmark child process.  On Unix the child is asked to
/// exit gracefully with SIGTERM and given a bounded grace period to
/// finish before being killed; on Windows it is terminated directly
/// (a no-op once the process already exited).
async fn shutdown_child(child: &mut std::process::Child) {
    #[cfg(unix)]
    {
        // An already-exited child reports pid 0 and must not be
        // signalled; `try_wait` also reaps it so the later `wait` is a
        // no-op.
        if let Ok(Some(_)) = child.try_wait() {
            return;
        }
        let pid = child.id();
        if pid != 0 {
            let _ = Command::new("kill")
                .args(["-TERM", &pid.to_string()])
                .status();
        }
        let deadline = tokio::time::Instant::now() + SHUTDOWN_GRACE;
        loop {
            match child.try_wait() {
                Ok(Some(_)) => return, // graceful exit within the grace period
                Ok(None) => {}
                Err(_) => break, // cannot wait (already reaped) — fall through
            }
            if tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }
    let _ = child.kill();
    let _ = child.wait();
}

/// Reaps a spawned proxy on drop — benchmark error paths must not leak
/// the child process (its listener would hold the port and break the
/// next target).  The success path calls [`ChildGuard::shutdown`],
/// which stops the child and disarms the guard so that dropping it
/// afterwards does not kill or wait again — unlike the former
/// `std::mem::forget`, this does not leak the `Child` handle (a
/// HANDLE on Windows).
struct ChildGuard(Option<std::process::Child>);

impl ChildGuard {
    fn new(child: std::process::Child) -> Self {
        Self(Some(child))
    }

    fn id(&self) -> u32 {
        self.0.as_ref().map_or(0, std::process::Child::id)
    }

    /// Bail if the child already exited — e.g. it rejected the config.
    /// Note this does NOT detect the squatter case: meow treats listener
    /// bind failure as non-fatal and stays alive, so a port squatter is
    /// caught by `ensure_port_free` before spawn (with an inherent small
    /// TOCTOU window), not by this check.
    fn ensure_alive(&mut self, target_name: &str) -> anyhow::Result<()> {
        if let Some(child) = self.0.as_mut() {
            match child.try_wait() {
                Ok(Some(status)) => {
                    anyhow::bail!(
                        "{target_name} exited early with {status} — is the port squatted?"
                    );
                }
                Err(e) => anyhow::bail!("{target_name}: cannot query child status: {e}"),
                Ok(None) => {}
            }
        }
        Ok(())
    }

    /// Success-path shutdown: gracefully stop the child, then disarm
    /// the guard so `Drop` is a no-op.
    async fn shutdown(mut self) {
        if let Some(child) = self.0.as_mut() {
            shutdown_child(child).await;
        }
        self.0 = None;
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            // Error path only — the success path disarms via
            // `shutdown()`. `kill()` precedes `wait()`, so the blocking
            // reap returns almost immediately; std's `Child` has no
            // async wait, so a brief block on an async worker is the
            // accepted trade-off (review N6). Bounded worst case
            // overall: a target that ignores SIGTERM costs up to
            // `SHUTDOWN_GRACE` (5 s) in `shutdown_child`, and targets
            // shut down sequentially, so a full multi-target run adds
            // up to 5 s × N.
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

async fn benchmark_target(
    binary: &Path,
    config: &Path,
    target_name: &str,
    args: &Args,
    only: Option<&str>,
    dns_config: Option<&Path>,
) -> anyhow::Result<BenchmarkResults> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_PORT}").parse()?;

    // Start a fresh echo server for this target (avoids TIME_WAIT port exhaustion)
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    eprintln!("[{target_name}] echo server on {echo_addr}");

    eprintln!("[{}] starting proxy: {}", target_name, binary.display());
    ensure_port_free(proxy_addr, target_name)?;

    // Start proxy process (SOCKS5 config for W1–W3).  The guard reaps
    // the child on every error path; the success path reaps it
    // explicitly via `ChildGuard::shutdown`.
    let mut child = ChildGuard::new(spawn_meow(binary, &args.binary_arg, config)?);

    let pid = child.id();

    // Wait for SOCKS5 port to be ready (the guard reaps the child if
    // this or any later step fails).  The guarded wait also fails fast
    // on a config-rejected early exit instead of burning the deadline.
    wait_for_port_guarded(proxy_addr, Duration::from_secs(10), &mut child, target_name).await?;
    eprintln!("[{target_name}] proxy ready on port {PROXY_PORT}");

    // Settle time
    tokio::time::sleep(Duration::from_secs(2)).await;

    // Binary size
    let binary_size = bench_binary_size::measure_binary_size(binary)?;
    eprintln!(
        "[{}] binary size: {:.1} MB",
        target_name,
        binary_size as f64 / 1048576.0
    );

    // Idle RSS
    let rss_idle = bench_memory::measure_rss(pid)?;
    eprintln!(
        "[{}] idle RSS: {:.1} MB",
        target_name,
        rss_idle as f64 / 1048576.0
    );

    // Warmup.  Each connection is bounded by the socks5 connect timeout
    // and the whole phase by a hard deadline, so a proxy whose dial path
    // stalls surfaces an error instead of wedging the harness.
    eprintln!("[{target_name}] warming up...");
    let warmup = async {
        for _ in 0..50 {
            if let Ok(mut s) = socks5_client::socks5_connect(proxy_addr, echo_addr).await {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let _ = tokio::time::timeout(Duration::from_secs(10), async {
                    s.write_all(&[0x42]).await?;
                    let mut buf = [0u8; 1];
                    s.read_exact(&mut buf).await?;
                    Ok::<_, std::io::Error>(())
                })
                .await;
            }
        }
    };
    if tokio::time::timeout(Duration::from_secs(30), warmup)
        .await
        .is_err()
    {
        eprintln!("[{target_name}] warmup deadline hit — continuing anyway");
    }

    let run_all = only.is_none();
    let only = only.unwrap_or("");

    // W1 — Throughput
    eprintln!("[{target_name}] benchmarking throughput...");
    let throughput = if run_all || only == "throughput" {
        bench_throughput::bench_throughput(proxy_addr, echo_addr).await?
    } else {
        vec![]
    };

    // W2 — Latency
    eprintln!("[{target_name}] benchmarking latency...");
    let latency = if run_all || only == "latency" {
        Some(bench_latency::bench_latency(proxy_addr, echo_addr, args.latency_iterations).await?)
    } else {
        None
    };

    // W3 — Connection rate (also measures peak RSS concurrently)
    eprintln!("[{target_name}] benchmarking connection rate...");
    let (conn_rate, rss_load) = if run_all || only == "connrate" {
        let rss_handle = tokio::spawn({
            let duration = args.duration;
            async move { bench_memory::measure_peak_rss(pid, duration).await }
        });
        let cr =
            bench_connrate::bench_conn_rate(proxy_addr, echo_addr, args.duration, args.concurrency)
                .await?;
        // Propagate rather than `unwrap_or(0)` — a zero here serializes
        // as a fake -100 % RSS "improvement" in compare.py.
        let peak_rss = rss_handle.await??;
        (Some(cr), peak_rss)
    } else {
        // Skipped: `rss_load` stays the idle reading — rendering shows
        // idle twice, which is the honest answer when no load ran.
        (None, rss_idle)
    };

    eprintln!(
        "[{}] load RSS: {:.1} MB",
        target_name,
        rss_load as f64 / 1048576.0
    );

    // Stop the SOCKS5 proxy process before starting the DNS process.
    // SIGTERM first on Unix with a bounded grace period for a graceful
    // shutdown; SIGKILL only if it does not exit in time.  On Windows
    // the child is terminated directly (a no-op once it exited).
    eprintln!("[{target_name}] stopping SOCKS5 proxy...");
    child.shutdown().await;
    echo_handle.abort();

    // W4 — DNS QPS (separate process with DNS-enabled config)
    let dns = match (run_all || only == "dns", dns_config) {
        (true, Some(dns_config)) => {
            eprintln!("[{}] starting DNS proxy: {}", target_name, binary.display());

            // spawn_meow inherits stderr like the primary child: if the
            // DNS config is rejected (e.g. mihomo chokes on a field) the
            // failure must be visible, not a silent `dns: null` in the
            // results.
            let dns_addr: SocketAddr = format!("127.0.0.1:{}", args.dns_port).parse()?;

            // A stale responder still bound on the DNS port answers the
            // probe and W4 would measure IT, not the spawned child —
            // the UDP squatter check runs before spawn so the failure is
            // a clear message rather than the child's exit-on-bind-error.
            if let Err(e) = ensure_udp_port_free(dns_addr, "DNS proxy") {
                eprintln!("[{target_name}] {e} — skipping W4");
                None
            } else {
                let mut dns_child =
                    ChildGuard::new(spawn_meow(binary, &args.binary_arg, dns_config)?);

                let ready = wait_for_udp_port_guarded(
                    dns_addr,
                    Duration::from_secs(10),
                    &mut dns_child,
                    "DNS proxy",
                )
                .await;
                if let Err(e) = ready {
                    eprintln!("[{target_name}] DNS port not ready: {e} — skipping W4");
                    None
                } else {
                    eprintln!("[{target_name}] DNS proxy ready on {dns_addr}");
                    tokio::time::sleep(Duration::from_secs(1)).await;

                    eprintln!("[{target_name}] benchmarking DNS QPS...");
                    let dns_result = bench_dns::bench_dns(dns_addr, args.duration).await;

                    // Graceful stop (SIGTERM + grace on Unix), no Child leak.
                    dns_child.shutdown().await;

                    match dns_result {
                        Ok(r) => Some(r),
                        Err(e) => {
                            eprintln!("[{target_name}] DNS bench error: {e}");
                            None
                        }
                    }
                }
            }
        }
        _ => None,
    };

    Ok(BenchmarkResults {
        target: target_name.to_string(),
        binary_size_bytes: binary_size,
        rss_idle_bytes: rss_idle,
        rss_load_bytes: rss_load,
        throughput,
        latency,
        conn_rate,
        dns,
    })
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let only = args.only.as_deref();

    // Reject unknown/partially-specified legs up front — a typo'd `--only`
    // otherwise yields an empty all-null report that exits 0.
    const VALID_ONLY: &[&str] = &[
        "throughput",
        "latency",
        "connrate",
        "dns",
        "memleak",
        "reload",
        "idle",
        "steady",
        "proxied",
    ];
    if let Some(o) = only {
        anyhow::ensure!(
            VALID_ONLY.contains(&o),
            "unknown --only '{o}' (expected one of: {})",
            VALID_ONLY.join(", ")
        );
        anyhow::ensure!(
            o != "proxied" || args.proxy_config.is_some(),
            "--only proxied requires --proxy-config (and --singbox-binary)"
        );
    }

    #[cfg(unix)]
    raise_nofile_limit();

    eprintln!("=== meow-rs benchmark suite ===\n");

    // Proxied-outbound leg (#558): a sing-box VLESS server fronts the echo
    // target so W1–W3 exercise a real outbound adapter. `--only proxied`
    // skips the direct legs entirely; a single-workload `--only` (e.g.
    // throughput) runs it on both direct and proxied legs.
    let want_proxied = args.proxy_config.is_some()
        && matches!(
            only,
            None | Some("proxied") | Some("throughput") | Some("latency") | Some("connrate")
        );
    if args.proxy_config.is_some() && !want_proxied {
        eprintln!("[warn] --proxy-config ignored: --only {only:?} runs no proxied leg");
    }
    if args.singbox_binary.is_some() && !want_proxied {
        eprintln!("[warn] --singbox-binary ignored: no proxied leg in this run");
    }

    // Standalone flows — each spawns its own proxy and exits:
    // `memleak` dials real external hosts; `reload` drives PUT /configs;
    // `idle`/`steady` are the ADR-0011 M-idle/M-steady footprint metrics.
    match only {
        Some("memleak") => return run_memleak_test(&args).await,
        Some("reload") => return run_reload_test(&args).await,
        Some("idle") | Some("steady") => return run_footprint_test(&args).await,
        _ => {}
    }

    let mut singbox = if want_proxied {
        let Some(bin) = &args.singbox_binary else {
            anyhow::bail!("--proxy-config requires --singbox-binary (the VLESS server half)");
        };
        eprintln!("[proxied] starting sing-box server: {}", bin.display());
        let vless_addr: SocketAddr = format!("127.0.0.1:{VLESS_SERVER_PORT}").parse()?;
        ensure_port_free(vless_addr, "sing-box")?;
        let (child, dir) = start_singbox_server(bin)?;
        let mut guard = ChildGuard::new(child);
        wait_for_port_guarded(vless_addr, Duration::from_secs(10), &mut guard, "sing-box").await?;
        eprintln!("[proxied] sing-box ready on {vless_addr}");
        Some((guard, dir))
    } else {
        None
    };

    // On the proxied legs `--only proxied` means the whole W1–W3 suite;
    // DNS is skipped (it never traverses the outbound adapter).
    let proxied_only = if only == Some("proxied") { None } else { only };
    let dns = args.dns_config.as_deref();

    // Benchmark Rust (direct) — skipped entirely on a `--only proxied` run.
    let rust_results = if only == Some("proxied") {
        None
    } else {
        Some(benchmark_target(&args.rust_binary, &args.config, "rust", &args, only, dns).await?)
    };

    // No TIME_WAIT cooldown between the direct and proxied legs: the
    // residual sockets are client-side on loopback ephemeral ports and
    // the same asymmetry applies to the go legs below, so the rust-vs-go
    // proxied comparison stays symmetric.
    let rust_proxied = if want_proxied {
        Some(
            benchmark_target(
                &args.rust_binary,
                args.proxy_config.as_deref().expect("gated above"),
                "rust-proxied",
                &args,
                proxied_only,
                None,
            )
            .await?,
        )
    } else {
        None
    };

    eprintln!();

    // Benchmark Go (if binary provided)
    let (go_results, go_proxied) = if let Some(go_binary) = &args.go_binary {
        // Wait for TIME_WAIT sockets to clear (macOS default is 15-30s)
        eprintln!("[*] waiting 60s for ephemeral ports to recycle...");
        tokio::time::sleep(Duration::from_secs(60)).await;
        let direct = if only == Some("proxied") {
            None
        } else {
            Some(benchmark_target(go_binary, &args.config, "go", &args, only, dns).await?)
        };
        let proxied = if want_proxied {
            Some(
                benchmark_target(
                    go_binary,
                    args.proxy_config.as_deref().expect("gated above"),
                    "go-proxied",
                    &args,
                    proxied_only,
                    None,
                )
                .await?,
            )
        } else {
            None
        };
        (direct, proxied)
    } else {
        eprintln!("[go] skipped (no --go-binary provided)\n");
        (None, None)
    };

    if let Some((guard, _dir)) = singbox.take() {
        eprintln!("[proxied] stopping sing-box...");
        guard.shutdown().await;
    }

    let report = ComparisonReport {
        meta: collect_meta(&args),
        rust: rust_results,
        rust_proxied,
        go: go_results,
        go_proxied,
    };

    // Output JSON
    let json = serde_json::to_string_pretty(&report)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("results written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    // Output markdown
    if args.markdown {
        eprintln!("\n--- Markdown ---\n");
        let md = results::render_markdown(&report);
        println!("{md}");
    }

    Ok(())
}

async fn run_memleak_test(args: &Args) -> anyhow::Result<()> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{}", args.memleak_port).parse()?;

    eprintln!(
        "[memleak] config: {}  binary: {}",
        args.memleak_config.display(),
        args.rust_binary.display()
    );

    if !args.memleak_config.exists() {
        anyhow::bail!(
            "memleak config not found: {}  (create one with an ECH-TLS-tunnel proxy or pass --memleak-config)",
            args.memleak_config.display()
        );
    }

    eprintln!("[memleak] starting proxy...");
    ensure_port_free(proxy_addr, "memleak proxy")?;
    // The guard reaps the child on every error path below (`?`
    // returns included); the success path stops it gracefully via
    // `ChildGuard::shutdown`.
    let mut child = ChildGuard::new(spawn_meow(
        &args.rust_binary,
        &args.binary_arg,
        &args.memleak_config,
    )?);

    let pid = child.id();

    wait_for_port_guarded(
        proxy_addr,
        Duration::from_secs(15),
        &mut child,
        "memleak proxy",
    )
    .await?;
    eprintln!(
        "[memleak] proxy ready (pid {pid}) on port {}",
        args.memleak_port
    );

    tokio::time::sleep(Duration::from_secs(2)).await;

    let rss_idle = bench_memory::measure_rss(pid)?;
    eprintln!(
        "[memleak] idle RSS: {:.1} MB",
        rss_idle as f64 / 1_048_576.0
    );

    let result = bench_memleak::bench_memleak(
        proxy_addr,
        pid,
        args.memleak_rounds,
        args.memleak_conns,
        args.concurrency,
    )
    .await?;

    // Stop the proxy gracefully: SIGTERM first on Unix with a bounded
    // grace period, SIGKILL only as a fallback; on Windows terminate
    // directly.  `shutdown` disarms the guard — no `Child` handle is
    // leaked.
    child.shutdown().await;

    let json = serde_json::to_string_pretty(&result)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("[memleak] results written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    if result.slope_kb_per_round > 50.0 && result.r_squared > 0.7 {
        std::process::exit(1);
    }
    Ok(())
}

/// Standalone ADR-0011 footprint workloads (`--only idle` / `--only
/// steady`, #558): spawn the proxy on the perf config and run the metric
/// collector.  M-idle holds N open connections and reports RSS per conn;
/// M-steady samples bytes-per-conn over the middle third of a sustained
/// conn-rate window.
async fn run_footprint_test(args: &Args) -> anyhow::Result<()> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_PORT}").parse()?;
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;

    ensure_port_free(proxy_addr, "proxy")?;
    let mut child = ChildGuard::new(spawn_meow(
        &args.rust_binary,
        &args.binary_arg,
        &args.config,
    )?);
    let pid = child.id();
    wait_for_port_guarded(proxy_addr, Duration::from_secs(10), &mut child, "proxy").await?;
    tokio::time::sleep(Duration::from_secs(2)).await;

    let result = match args.only.as_deref() {
        Some("idle") => serde_json::to_string_pretty(
            &bench_idle_conns::bench_idle_conns(
                proxy_addr,
                echo_addr,
                args.idle_conns,
                args.idle_hold_secs,
                pid,
            )
            .await?,
        )?,
        _ => serde_json::to_string_pretty(
            &bench_connrate::bench_connrate_steady_state(
                proxy_addr,
                echo_addr,
                args.duration,
                args.concurrency,
                pid,
            )
            .await?,
        )?,
    };

    child.shutdown().await;
    echo_handle.abort();

    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &result)?;
        eprintln!("results written to {}", output_path.display());
    } else {
        println!("{result}");
    }
    Ok(())
}

/// Fixed port for the reload workload's datapath probe echo listener.
/// The two reload configs name it in a `DST-PORT` rule that flips
/// between a working outbound and REJECT, which is how the workload
/// verifies a committed config actually reached the datapath.
const RELOAD_PROBE_PORT: u16 = 17895;

/// The probe-rule list item `config-bench-reload.yaml` carries; the B
/// variant is generated by swapping its target to REJECT.  Matched as a
/// full trimmed line — a comment quoting the rule or a longer rule like
/// `DST-PORT,17895,bench-direct-foo` must not count as the probe rule.
const RELOAD_PROBE_RULE: &str = "- DST-PORT,17895,bench-direct";

/// Standalone config-reload workload (`--only reload`, #558): steady echo
/// load while `PUT /configs` runs `args.reloads` times, alternating
/// between `--reload-config` and a generated REJECT-probe variant, then
/// probes datapath parity AND verifies the last committed config is
/// observable.  Requires `--reload-config` with `external-controller`
/// bound to `--api-port`, `mixed-port` 17890, and the
/// `DST-PORT,17895,bench-direct` probe rule.
async fn run_reload_test(args: &Args) -> anyhow::Result<()> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_PORT}").parse()?;
    let api_addr: SocketAddr = format!("127.0.0.1:{}", args.api_port).parse()?;
    let probe_addr: SocketAddr = format!("127.0.0.1:{RELOAD_PROBE_PORT}").parse()?;

    if !args.reload_config.exists() {
        anyhow::bail!(
            "reload config not found: {}  (needs external-controller on port {})",
            args.reload_config.display(),
            args.api_port
        );
    }

    // Build the B variant: identical except the probe rule targets
    // REJECT, so a committed generation is observable through the
    // datapath.  Fails loudly if the config drifted from the expected
    // probe-rule line — a silently-absent rule would make every commit
    // look verified.
    let config_text = std::fs::read_to_string(&args.reload_config)?;
    anyhow::ensure!(
        config_text
            .lines()
            .filter(|l| l.trim() == RELOAD_PROBE_RULE)
            .count()
            == 1,
        "reload config {} must contain exactly one '{RELOAD_PROBE_RULE}' list item \
         (see config-bench-reload.yaml)",
        args.reload_config.display()
    );
    // Cheap contract check while the text is in hand: a config whose
    // external-controller doesn't bind --api-port otherwise surfaces
    // only as a 10 s port-wait timeout.
    anyhow::ensure!(
        config_text.contains("external-controller")
            && config_text.contains(&format!(":{}", args.api_port)),
        "reload config {} must set 'external-controller' bound to --api-port {}",
        args.reload_config.display(),
        args.api_port
    );
    // Swap the target on the one matching list-item line (line-anchored,
    // so a comment quoting the rule is never rewritten).
    let mut alt_text = String::with_capacity(config_text.len());
    let mut swapped = false;
    for line in config_text.lines() {
        if !swapped && line.trim() == RELOAD_PROBE_RULE {
            alt_text.push_str(&line.replacen("bench-direct", "REJECT", 1));
            swapped = true;
        } else {
            alt_text.push_str(line);
        }
        alt_text.push('\n');
    }
    debug_assert!(swapped, "probe rule line guaranteed by the check above");
    let alt_dir = tempfile::tempdir()?;
    let alt_path = alt_dir.path().join("config-bench-reload-b.yaml");
    std::fs::write(&alt_path, alt_text)?;

    // Free-port checks before binding anything — a squatter on the
    // probe port otherwise surfaces as a bare "Address already in use"
    // with no context.
    ensure_port_free(proxy_addr, "reload proxy")?;
    ensure_port_free(api_addr, "reload API")?;
    ensure_port_free(probe_addr, "reload probe echo")?;
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    let (_probe_echo_addr, probe_echo_handle) =
        echo_server::start_echo_server_on(probe_addr).await?;
    let mut child = ChildGuard::new(spawn_meow(
        &args.rust_binary,
        &args.binary_arg,
        &args.reload_config,
    )?);

    wait_for_port_guarded(
        proxy_addr,
        Duration::from_secs(10),
        &mut child,
        "reload proxy",
    )
    .await?;
    wait_for_port_guarded(api_addr, Duration::from_secs(10), &mut child, "reload API").await?;
    eprintln!("[reload] proxy + API ready");
    tokio::time::sleep(Duration::from_secs(2)).await;

    let result = bench_reload::bench_reload(
        bench_reload::ReloadTarget {
            proxy: proxy_addr,
            echo: echo_addr,
            probe_addr,
            api: api_addr,
        },
        &args.reload_config,
        &alt_path,
        args.duration,
        args.concurrency,
        args.reloads,
    )
    .await?;

    child.shutdown().await;
    echo_handle.abort();
    probe_echo_handle.abort();
    // Free the tempdir explicitly: `std::process::exit` below skips
    // destructors and would leak it into /tmp.
    drop(alt_dir);

    let json = serde_json::to_string_pretty(&result)?;
    if let Some(output_path) = &args.output {
        std::fs::write(output_path, &json)?;
        eprintln!("results written to {}", output_path.display());
    } else {
        println!("{json}");
    }

    // Hard failure signals: any rejected reload means the rebuild chain
    // broke under load — that's a regression, not a measurement.  A
    // datapath that fails verification (204s whose routing never landed),
    // a datapath dead after commit, or a post-rate far below the
    // pre-reload baseline are the same class of failure.
    if result.reloads_ok < result.reloads_attempted
        || result.datapath_verify_failures > 0
        || (result.post_reload_conns_per_sec == 0.0 && result.post_reload_errors > 0)
        || (result.pre_reload_conns_per_sec > 0.0
            && result.post_reload_conns_per_sec < 0.5 * result.pre_reload_conns_per_sec)
    {
        std::process::exit(1);
    }
    Ok(())
}
