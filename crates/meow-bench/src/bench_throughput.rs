use anyhow::Context;
use std::net::SocketAddr;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::socks5_client::socks5_connect;

/// Stall bound on post-connect IO: a datapath that accepts but never
/// echoes must fail the leg, not hang the suite.  Generous — a healthy
/// 64 MB loopback transfer finishes in well under a second.
const TRANSFER_TIMEOUT: Duration = Duration::from_secs(120);
/// Per-round-trip bound for the small-message loop.
const MSG_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputResult {
    pub label: String,
    pub total_bytes: u64,
    pub elapsed_secs: f64,
    pub gbps: f64,
}

/// Large transfer: write `size` bytes, read them back, using concurrent read+write.
async fn run_large_transfer(
    proxy: SocketAddr,
    echo: SocketAddr,
    size: usize,
) -> anyhow::Result<(u64, f64)> {
    let stream = socks5_connect(proxy, echo)
        .await
        .with_context(|| format!("large transfer connect to {echo}"))?;
    let (rd, wr) = tokio::io::split(stream);

    let start = Instant::now();

    let write_task = tokio::spawn(async move {
        let mut wr = wr;
        let chunk = vec![0xABu8; 64 * 1024];
        let mut remaining = size;
        while remaining > 0 {
            let n = remaining.min(chunk.len());
            wr.write_all(&chunk[..n]).await?;
            remaining -= n;
        }
        Ok::<_, std::io::Error>(wr)
    });

    let read_task = tokio::spawn(async move {
        let mut rd = rd;
        let mut buf = vec![0u8; 64 * 1024];
        let mut received = 0usize;
        while received < size {
            let n = rd.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            received += n;
        }
        Ok::<_, std::io::Error>(received)
    });

    let received = tokio::time::timeout(TRANSFER_TIMEOUT, read_task)
        .await
        .map_err(|_| {
            anyhow::anyhow!("large transfer read stalled after {TRANSFER_TIMEOUT:?}")
        })???;
    let _wr = write_task.await??;
    let elapsed = start.elapsed().as_secs_f64();
    anyhow::ensure!(
        received == size,
        "large transfer ended early: received {received} of {size} echo bytes"
    );

    let total = (size + received) as u64;
    Ok((total, elapsed))
}

/// Small-message test: single connection, many round-trips of `msg_size` bytes.
async fn run_small_messages(
    proxy: SocketAddr,
    echo: SocketAddr,
    msg_size: usize,
    count: usize,
) -> anyhow::Result<(u64, f64)> {
    let mut stream = socks5_connect(proxy, echo)
        .await
        .with_context(|| format!("small messages connect to {echo}"))?;
    let msg = vec![0xABu8; msg_size];
    let mut buf = vec![0u8; msg_size];
    let mut total_bytes = 0u64;

    let start = Instant::now();
    for _ in 0..count {
        tokio::time::timeout(MSG_TIMEOUT, async {
            stream.write_all(&msg).await?;
            stream.read_exact(&mut buf).await?;
            Ok::<_, std::io::Error>(())
        })
        .await
        .map_err(|_| anyhow::anyhow!("small message round-trip stalled after {MSG_TIMEOUT:?}"))??;
        total_bytes += (msg_size * 2) as u64;
    }
    let elapsed = start.elapsed().as_secs_f64();

    Ok((total_bytes, elapsed))
}

pub async fn bench_throughput(
    proxy: SocketAddr,
    echo: SocketAddr,
) -> anyhow::Result<Vec<ThroughputResult>> {
    let mut results = Vec::new();

    // Small messages: single connection, many round-trips
    {
        let label = "4 KB x 10000";
        let (total_bytes, elapsed) = run_small_messages(proxy, echo, 4 * 1024, 10_000).await?;
        let gbps = (total_bytes as f64 * 8.0) / elapsed / 1e9;
        eprintln!("  throughput {label}: {gbps:.2} Gbps");
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: elapsed,
            gbps,
        });
    }

    // Medium transfers: multiple connections
    {
        let label = "1 MB x 10";
        let mut total_bytes = 0u64;
        let mut total_elapsed = 0.0f64;
        for _ in 0..10 {
            let (bytes, elapsed) = run_large_transfer(proxy, echo, 1024 * 1024).await?;
            total_bytes += bytes;
            total_elapsed += elapsed;
        }
        let gbps = (total_bytes as f64 * 8.0) / total_elapsed / 1e9;
        eprintln!("  throughput {label}: {gbps:.2} Gbps");
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: total_elapsed,
            gbps,
        });
    }

    // Large single transfer
    {
        let label = "64 MB x 1";
        let (total_bytes, elapsed) = run_large_transfer(proxy, echo, 64 * 1024 * 1024).await?;
        let gbps = (total_bytes as f64 * 8.0) / elapsed / 1e9;
        eprintln!("  throughput {label}: {gbps:.2} Gbps");
        results.push(ThroughputResult {
            label: label.to_string(),
            total_bytes,
            elapsed_secs: elapsed,
            gbps,
        });
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn truncated_echo_is_not_a_throughput_result() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            stream
                .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut payload = [0; 4096];
            stream.read_exact(&mut payload).await.unwrap();
            // Accept the entire upload but return only half of its echo.
            stream.write_all(&payload[..2048]).await.unwrap();
        });
        let error = tokio::time::timeout(
            Duration::from_secs(5),
            run_large_transfer(proxy, "127.0.0.1:9".parse().unwrap(), 4096),
        )
        .await
        .expect("truncated echo should finish promptly")
        .expect_err("an incomplete transfer must not produce a throughput score");
        assert!(error.to_string().contains("received 2048 of 4096"));
        server.await.unwrap();
    }
}
