use std::net::SocketAddr;
use std::time::{Duration, Instant};

use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RecordType};
use hickory_proto::serialize::binary::BinEncodable;
use tokio::net::UdpSocket;

#[derive(Debug, Clone, serde::Serialize)]
pub struct DnsResult {
    pub total_queries: usize,
    pub duration_secs: f64,
    pub qps: f64,
    pub p50_us: f64,
    pub p99_us: f64,
    pub cache_hit_queries: usize,
    pub cache_miss_queries: usize,
}

fn build_query(name: &str, id: u16) -> anyhow::Result<Vec<u8>> {
    let mut msg = Message::new(id, MessageType::Query, OpCode::Query);
    msg.metadata.recursion_desired = true;

    let name: Name = name.parse()?;
    let query = Query::query(name, RecordType::A);
    msg.add_query(query);

    Ok(msg.to_bytes()?)
}

async fn send_dns_query(
    socket: &UdpSocket,
    dns_addr: SocketAddr,
    name: &str,
    id: u16,
) -> anyhow::Result<Duration> {
    let query = build_query(name, id)?;
    let start = Instant::now();
    socket.send_to(&query, dns_addr).await?;

    let mut buf = [0u8; 4096];
    // 2s timeout per query
    tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buf))
        .await
        .map_err(|_| anyhow::anyhow!("DNS query timeout for {name}"))??;

    Ok(start.elapsed())
}

pub async fn bench_dns(dns_addr: SocketAddr, duration_secs: u64) -> anyhow::Result<DnsResult> {
    const WARMUP_DOMAINS: usize = 500;
    const TOTAL_QUERIES: usize = 5000;

    // Cached domains: small set, 50% of traffic will hit these. The
    // `.bench` TLD deliberately avoids every entry in mihomo's default
    // fake-ip-filter (*.lan, *.invalid, *.test, ...) so both binaries
    // synthesize fake-IP answers locally.
    let cached_domains: Vec<String> = (0..WARMUP_DOMAINS)
        .map(|i| format!("bench-cache-{i}.bench."))
        .collect();

    // Unique domains: generate fresh names so they're cache misses
    let miss_base = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let socket = UdpSocket::bind("127.0.0.1:0").await?;

    // Warmup: prime the cache with WARMUP_DOMAINS entries
    eprintln!("  [dns] warming up cache ({WARMUP_DOMAINS} domains)...");
    for (i, domain) in cached_domains.iter().enumerate() {
        if let Err(e) = send_dns_query(&socket, dns_addr, domain, i as u16).await {
            eprintln!("  [dns] warmup error for {domain}: {e}");
        }
    }

    // Benchmark: TOTAL_QUERIES total, alternating hit/miss
    eprintln!("  [dns] running {TOTAL_QUERIES} queries...");
    let mut latencies: Vec<f64> = Vec::with_capacity(TOTAL_QUERIES);
    let mut cache_hit_queries = 0usize;
    let mut cache_miss_queries = 0usize;

    let bench_start = Instant::now();
    let deadline = bench_start + Duration::from_secs(duration_secs);

    let mut query_id = 1u16;
    let mut completed = 0usize;

    while completed < TOTAL_QUERIES && Instant::now() < deadline {
        let domain = if completed.is_multiple_of(2) {
            // Cache hit: use a pre-warmed domain
            cache_hit_queries += 1;
            cached_domains[completed % WARMUP_DOMAINS].clone()
        } else {
            // Cache miss: unique domain
            cache_miss_queries += 1;
            format!("bench-miss-{miss_base}-{completed}.bench.")
        };

        match send_dns_query(&socket, dns_addr, &domain, query_id).await {
            Ok(elapsed) => {
                latencies.push(elapsed.as_secs_f64() * 1e6);
            }
            Err(e) => {
                eprintln!("  [dns] query error: {e}");
            }
        }

        query_id = query_id.wrapping_add(1);
        completed += 1;
    }

    let elapsed = bench_start.elapsed().as_secs_f64();
    let actual_queries = latencies.len();

    latencies.sort_by(|a, b| a.partial_cmp(b).unwrap());

    let percentile = |p: f64| -> f64 {
        if latencies.is_empty() {
            return 0.0;
        }
        let idx = ((p / 100.0) * (latencies.len() - 1) as f64).round() as usize;
        latencies[idx]
    };

    let qps = actual_queries as f64 / elapsed;

    eprintln!(
        "  [dns] {} queries in {:.1}s = {:.0} QPS, p50={:.0}µs p99={:.0}µs",
        actual_queries,
        elapsed,
        qps,
        percentile(50.0),
        percentile(99.0),
    );

    Ok(DnsResult {
        total_queries: actual_queries,
        duration_secs: elapsed,
        qps,
        p50_us: percentile(50.0),
        p99_us: percentile(99.0),
        cache_hit_queries,
        cache_miss_queries,
    })
}
