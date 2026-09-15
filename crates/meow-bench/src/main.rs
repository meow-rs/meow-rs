mod bench_binary_size;
mod bench_connrate;
mod bench_dns;
mod bench_idle_conns;
mod bench_latency;
mod bench_memleak;
mod bench_memory;
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

    /// Run only a specific benchmark (throughput, latency, connrate, dns, memleak)
    #[arg(long)]
    only: Option<String>,

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

async fn wait_for_port(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            return Ok(());
        }
        if tokio::time::Instant::now() >= deadline {
            anyhow::bail!("timeout waiting for {addr} to become reachable");
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

async fn wait_for_udp_port(addr: SocketAddr, timeout: Duration) -> anyhow::Result<()> {
    use hickory_proto::op::{Message, MessageType, OpCode, Query};
    use hickory_proto::rr::{Name, RecordType};
    use hickory_proto::serialize::binary::BinEncodable;
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
        let _ = sock.send_to(&probe, addr).await;
        let mut buf = [0u8; 512];
        let ready =
            tokio::time::timeout(Duration::from_millis(200), sock.recv_from(&mut buf)).await;
        if ready.is_ok() {
            return Ok(());
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
) -> anyhow::Result<BenchmarkResults> {
    let proxy_addr: SocketAddr = format!("127.0.0.1:{PROXY_PORT}").parse()?;

    // Start a fresh echo server for this target (avoids TIME_WAIT port exhaustion)
    let (echo_addr, echo_handle) = echo_server::start_echo_server().await?;
    eprintln!("[{target_name}] echo server on {echo_addr}");

    eprintln!("[{}] starting proxy: {}", target_name, binary.display());

    // Start proxy process (SOCKS5 config for W1–W3).  The guard reaps
    // the child on every error path; the success path reaps it
    // explicitly via `ChildGuard::shutdown`.
    let child = ChildGuard::new(
        Command::new(binary)
            .arg(&args.binary_arg)
            .arg(config.as_os_str())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start {}: {}", binary.display(), e))?,
    );

    let pid = child.id();

    // Wait for SOCKS5 port to be ready (the guard reaps the child if
    // this or any later step fails).
    wait_for_port(proxy_addr, Duration::from_secs(10)).await?;
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

    let run_all = args.only.is_none();
    let only = args.only.as_deref().unwrap_or("");

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
        let peak_rss = rss_handle.await?.unwrap_or(0);
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
    let dns = match (run_all || only == "dns", args.dns_config.as_ref()) {
        (true, Some(dns_config)) => {
            eprintln!("[{}] starting DNS proxy: {}", target_name, binary.display());

            let dns_child = ChildGuard::new(
                Command::new(binary)
                    .arg(&args.binary_arg)
                    .arg(dns_config.as_os_str())
                    .stdout(Stdio::null())
                    // Inherit stderr like the primary child: if the DNS
                    // config is rejected (e.g. mihomo chokes on a field)
                    // the failure must be visible, not a silent
                    // `dns: null` in the results.
                    .stderr(Stdio::inherit())
                    .spawn()
                    .map_err(|e| anyhow::anyhow!("failed to start DNS proxy: {e}"))?,
            );

            let dns_addr: SocketAddr = format!("127.0.0.1:{}", args.dns_port).parse()?;

            let ready = wait_for_udp_port(dns_addr, Duration::from_secs(10)).await;
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

    eprintln!("=== meow-rs benchmark suite ===\n");

    // Memleak test is a standalone flow — it dials real external hosts through
    // the proxy instead of using a local echo server.
    if args.only.as_deref() == Some("memleak") {
        return run_memleak_test(&args).await;
    }

    // Benchmark Rust
    let rust_results = benchmark_target(&args.rust_binary, &args.config, "rust", &args).await?;

    eprintln!();

    // Benchmark Go (if binary provided)
    let go_results = if let Some(go_binary) = &args.go_binary {
        // Wait for TIME_WAIT sockets to clear (macOS default is 15-30s)
        eprintln!("[*] waiting 60s for ephemeral ports to recycle...");
        tokio::time::sleep(Duration::from_secs(60)).await;
        Some(benchmark_target(go_binary, &args.config, "go", &args).await?)
    } else {
        eprintln!("[go] skipped (no --go-binary provided)\n");
        None
    };

    let report = ComparisonReport {
        meta: collect_meta(&args),
        rust: rust_results,
        go: go_results,
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
    // The guard reaps the child on every error path below (`?`
    // returns included); the success path stops it gracefully via
    // `ChildGuard::shutdown`.
    let child = ChildGuard::new(
        Command::new(&args.rust_binary)
            .args(["-f", &args.memleak_config.to_string_lossy()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| anyhow::anyhow!("failed to start {}: {e}", args.rust_binary.display()))?,
    );

    let pid = child.id();

    wait_for_port(proxy_addr, Duration::from_secs(15)).await?;
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
