use std::net::SocketAddr;
use std::time::Instant;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5_client::socks5_connect;

#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencyResult {
    pub iterations: usize,
    pub p50_us: f64,
    pub p95_us: f64,
    pub p99_us: f64,
    pub min_us: f64,
    pub max_us: f64,
}

pub async fn bench_latency(
    proxy: SocketAddr,
    echo: SocketAddr,
    iterations: usize,
) -> anyhow::Result<LatencyResult> {
    anyhow::ensure!(iterations > 0, "latency requires at least 1 iteration");
    let mut latencies = Vec::with_capacity(iterations);

    for _ in 0..iterations {
        let start = Instant::now();
        let mut stream = socks5_connect(proxy, echo).await?;
        stream.write_all(&[0x42]).await?;
        let mut buf = [0u8; 1];
        stream.read_exact(&mut buf).await?;
        drop(stream);
        latencies.push(start.elapsed().as_secs_f64() * 1e6); // microseconds
    }

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let percentile = |p: f64| -> f64 {
        let idx = ((p / 100.0) * (latencies.len() - 1) as f64).round() as usize;
        latencies[idx]
    };

    let result = LatencyResult {
        iterations,
        p50_us: percentile(50.0),
        p95_us: percentile(95.0),
        p99_us: percentile(99.0),
        min_us: latencies[0],
        max_us: *latencies.last().unwrap(),
    };

    eprintln!(
        "  latency p50={:.0}us p99={:.0}us min={:.0}us max={:.0}us",
        result.p50_us, result.p99_us, result.min_us, result.max_us,
    );

    Ok(result)
}
