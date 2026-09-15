use std::net::SocketAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::bench_memory::measure_rss;
use crate::socks5_client::socks5_connect;

/// Per-connection echo deadline: a proxy whose echo never returns must not
/// wedge a worker forever — time it out and move on to the next conn.
const ECHO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConnRateResult {
    pub duration_secs: f64,
    pub total_connections: u64,
    pub connections_per_sec: f64,
    /// Connections whose echo phase hit the deadline (a proxy that
    /// accepted the CONNECT but never answered).
    pub echo_timeouts: u64,
}

pub async fn bench_conn_rate(
    proxy: SocketAddr,
    echo: SocketAddr,
    duration_secs: u64,
    concurrency: usize,
) -> anyhow::Result<ConnRateResult> {
    let counter = Arc::new(AtomicU64::new(0));
    let echo_timeouts = Arc::new(AtomicU64::new(0));
    let start = Instant::now();
    let deadline = start + Duration::from_secs(duration_secs);

    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let counter = Arc::clone(&counter);
        let echo_timeouts = Arc::clone(&echo_timeouts);
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let Ok(mut stream) = socks5_connect(proxy, echo).await else {
                    continue;
                };
                let timed_out = tokio::time::timeout(ECHO_TIMEOUT, async {
                    if stream.write_all(&[0x42]).await.is_ok() {
                        let mut buf = [0u8; 1];
                        let _ = stream.read_exact(&mut buf).await;
                    }
                })
                .await
                .is_err();
                drop(stream);
                if timed_out {
                    echo_timeouts.fetch_add(1, Ordering::Relaxed);
                }
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    for h in handles {
        let _ = h.await;
    }

    let total = counter.load(Ordering::Relaxed);
    let timeouts = echo_timeouts.load(Ordering::Relaxed);
    // Measured elapsed, not the configured duration: workers may run past
    // the deadline by up to CONNECT_TIMEOUT + ECHO_TIMEOUT (~20 s) on
    // their last in-flight conn, so dividing by `duration_secs` would
    // understate the rate.
    let actual_elapsed = start.elapsed().as_secs_f64();
    let cps = total as f64 / actual_elapsed;

    eprintln!("  conn-rate: {total} connections in {actual_elapsed:.1}s = {cps:.0}/s");
    if timeouts > 0 {
        eprintln!("  echo-timeouts: {timeouts} connections never answered their echo");
    }

    Ok(ConnRateResult {
        duration_secs: actual_elapsed,
        total_connections: total,
        connections_per_sec: cps,
        echo_timeouts: timeouts,
    })
}

// Not yet wired into main.rs; infrastructure added for M2 close-summary.
#[allow(dead_code)]
#[derive(Debug, Clone, serde::Serialize)]
pub struct SteadyStateResult {
    pub sample_count: usize,
    pub median_bytes_per_conn: f64,
    pub p95_bytes_per_conn: f64,
    pub median_rss_bytes: u64,
}

/// Steady-state bytes-per-connection measurement (ADR-0011 §2 M-steady).
///
/// Runs a `bench_conn_rate`-style workload for `duration_secs`, then samples
/// `(rss_bytes, live_conn_count)` at 1 Hz over the **middle** `sample_secs`
/// window.  Returns the median and p95 of `rss_bytes / live_conn_count`.
///
/// `live_conn_count` is approximated from the `Statistics` REST endpoint, or
/// from the active-connection counter exposed by the proxy via its process
/// metrics.  For this baseline implementation we approximate it as
/// `concurrency` (the number of inflight concurrent requests) — the true live
/// count converges to `concurrency` at steady state since each worker keeps
/// one connection open at a time.
///
/// This is the headline M2 close-summary number per architect directive
/// 2026-05-12.
// Not yet wired into main.rs; infrastructure added for M2 close-summary.
#[allow(dead_code)]
pub async fn bench_connrate_steady_state(
    proxy: SocketAddr,
    echo: SocketAddr,
    duration_secs: u64,
    concurrency: usize,
    proxy_pid: u32,
) -> anyhow::Result<SteadyStateResult> {
    let counter = Arc::new(AtomicU64::new(0));
    let deadline = Instant::now() + Duration::from_secs(duration_secs);

    // Spawn connrate workers (same pattern as bench_conn_rate).
    let mut handles = Vec::new();
    for _ in 0..concurrency {
        let counter = Arc::clone(&counter);
        handles.push(tokio::spawn(async move {
            while Instant::now() < deadline {
                let Ok(mut stream) = socks5_connect(proxy, echo).await else {
                    continue;
                };
                let _ = tokio::time::timeout(ECHO_TIMEOUT, async {
                    if stream.write_all(&[0x42]).await.is_ok() {
                        let mut buf = [0u8; 1];
                        let _ = stream.read_exact(&mut buf).await;
                    }
                })
                .await;
                drop(stream);
                counter.fetch_add(1, Ordering::Relaxed);
            }
        }));
    }

    // Compute the middle-third sampling window.
    let warmup = duration_secs / 3;
    let sample_end = 2 * duration_secs / 3;
    let start = Instant::now();

    // Skip warmup.
    while start.elapsed().as_secs() < warmup {
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    // Sample at 1 Hz over the middle third.
    let mut samples: Vec<f64> = Vec::new();
    let mut rss_samples: Vec<u64> = Vec::new();
    while start.elapsed().as_secs() < sample_end {
        if let Ok(rss) = measure_rss(proxy_pid) {
            // At steady state, concurrency == number of inflight connections.
            let bytes_per_conn = rss as f64 / concurrency as f64;
            samples.push(bytes_per_conn);
            rss_samples.push(rss);
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
    }

    // Wait for workers.
    for h in handles {
        let _ = h.await;
    }

    // Compute median + p95.
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
    rss_samples.sort();

    let n = samples.len();
    let median_bytes_per_conn = if n > 0 { samples[n / 2] } else { 0.0 };
    let p95_bytes_per_conn = if n > 0 {
        samples[(n as f64 * 0.95) as usize]
    } else {
        0.0
    };
    let median_rss_bytes = if rss_samples.is_empty() {
        0
    } else {
        rss_samples[rss_samples.len() / 2]
    };

    eprintln!(
        "  steady-state: {n} samples  median {:.0} bytes/conn  p95 {:.0} bytes/conn  median RSS {:.1} MB",
        median_bytes_per_conn,
        p95_bytes_per_conn,
        median_rss_bytes as f64 / 1_048_576.0,
    );

    Ok(SteadyStateResult {
        sample_count: n,
        median_bytes_per_conn,
        p95_bytes_per_conn,
        median_rss_bytes,
    })
}
