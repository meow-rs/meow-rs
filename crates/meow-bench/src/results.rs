use crate::bench_connrate::ConnRateResult;
use crate::bench_dns::DnsResult;
use crate::bench_latency::LatencyResult;
use crate::bench_throughput::ThroughputResult;

#[derive(Debug, Clone, serde::Serialize)]
pub struct BenchmarkResults {
    pub target: String,
    pub binary_size_bytes: u64,
    pub rss_idle_bytes: u64,
    pub rss_load_bytes: u64,
    pub throughput: Vec<ThroughputResult>,
    /// `None` when a `--only` run skipped the workload — never a zeroed
    /// struct, so consumers can distinguish "not measured" from "measured 0".
    pub latency: Option<LatencyResult>,
    pub conn_rate: Option<ConnRateResult>,
    pub dns: Option<DnsResult>,
}

/// Provenance for a run: enough to tell two artifacts apart without
/// joining run IDs back to commits through the CI API. All fields are
/// best-effort — missing metadata degrades to `None`, never an error.
#[derive(Debug, serde::Serialize)]
pub struct BenchMeta {
    /// `CARGO_PKG_VERSION` of the meow-bench build (tracks the workspace).
    pub meow_version: String,
    /// What the *tested* binary reports via `-v` (e.g. "Meow Meta
    /// 0.21.2") — unlike `git_sha` this follows `--rust-binary`, so a
    /// foreign or stale binary can't be mislabeled by the checkout's HEAD.
    pub tested_version: Option<String>,
    /// `git rev-parse HEAD` when run inside a checkout. Describes the
    /// harness source tree, NOT necessarily the tested binary.
    pub git_sha: Option<String>,
    /// `rustc --version` output (the toolchain on PATH, not necessarily
    /// the one that built the tested binary).
    pub rustc: Option<String>,
    /// mihomo release tag, exported as `MIHOMO_VERSION` by bench.sh.
    pub mihomo_version: Option<String>,
    /// e.g. "linux-x86_64", "macos-aarch64".
    pub platform: String,
    /// Steady-state duration per workload as *invoked*. Contrast with
    /// `conn_rate.duration_secs`, which is the *measured* elapsed time.
    pub duration_secs: u64,
}

#[derive(Debug, serde::Serialize)]
pub struct ComparisonReport {
    pub meta: BenchMeta,
    pub rust: BenchmarkResults,
    pub go: Option<BenchmarkResults>,
}

fn fmt_dns_rows(rust: Option<&DnsResult>, go: Option<&DnsResult>) -> String {
    match (rust, go) {
        (Some(r), Some(g)) => format!(
            "| DNS QPS | {:.0} | {:.0} | {} |\n| DNS p99 latency | {:.0} µs | {:.0} µs | {} |\n",
            g.qps,
            r.qps,
            fmt_delta(r.qps, g.qps, true),
            g.p99_us,
            r.p99_us,
            fmt_delta(r.p99_us, g.p99_us, false),
        ),
        (Some(r), None) => format!(
            "| DNS QPS | N/A | {:.0} | N/A |\n| DNS p99 latency | N/A | {:.0} µs | N/A |\n",
            r.qps, r.p99_us,
        ),
        _ => String::new(),
    }
}

fn fmt_dns_rows_rust_only(rust: Option<&DnsResult>) -> String {
    match rust {
        Some(r) => format!(
            "| DNS QPS | {:.0} |\n| DNS p99 latency | {:.0} µs |\n",
            r.qps, r.p99_us,
        ),
        None => String::new(),
    }
}

fn fmt_bytes(b: u64) -> String {
    let mb = b as f64 / (1024.0 * 1024.0);
    format!("{mb:.1} MB")
}

fn fmt_delta(rust: f64, go: f64, _higher_is_better: bool) -> String {
    if go == 0.0 {
        return "N/A".to_string();
    }
    let pct = ((rust - go) / go) * 100.0;
    let sign = if pct > 0.0 { "+" } else { "" };
    format!("{sign}{pct:.0}%")
}

fn fmt_meta_line(meta: &BenchMeta) -> String {
    let sha = meta
        .git_sha
        .as_deref()
        .map(|s| format!(" `{}`", s.get(..10).unwrap_or(s)))
        .unwrap_or_default();
    let rustc = meta
        .rustc
        .as_deref()
        .map(|s| format!(" · {s}"))
        .unwrap_or_default();
    let mihomo = meta
        .mihomo_version
        .as_deref()
        .map(|s| format!(" · mihomo {s}"))
        .unwrap_or_default();
    // Prefer the tested binary's own `-v` report; fall back to the
    // harness's package version (equal whenever they share a build).
    let tested = meta
        .tested_version
        .as_deref()
        .map_or(meta.meow_version.as_str(), |s| {
            s.strip_prefix("Meow Meta ").unwrap_or(s)
        });
    format!("meow-rs {tested}{sha}{rustc}{mihomo}")
}

pub fn render_markdown(report: &ComparisonReport) -> String {
    let r = &report.rust;
    // `None` when a `--only` run skipped throughput entirely.
    let headline_tp = r
        .throughput
        .iter()
        .find(|t| t.label.starts_with("64 MB"))
        .or_else(|| r.throughput.last());
    let rust_tp_str =
        headline_tp.map_or_else(|| "N/A".to_string(), |t| format!("{:.2} Gbps", t.gbps));
    let us = |v: Option<f64>| v.map_or_else(|| "N/A".to_string(), |v| format!("{v:.0} us"));
    let num = |v: Option<f64>| v.map_or_else(|| "N/A".to_string(), |v| format!("{v:.0}"));
    let lat_p50 = r.latency.as_ref().map(|l| l.p50_us);
    let lat_p99 = r.latency.as_ref().map(|l| l.p99_us);
    let cr = r.conn_rate.as_ref().map(|c| c.connections_per_sec);

    if let Some(g) = &report.go {
        let go_tp = g
            .throughput
            .iter()
            .find(|t| t.label.starts_with("64 MB"))
            .or_else(|| g.throughput.last());
        let go_tp_str = go_tp.map_or_else(|| "N/A".to_string(), |t| format!("{:.2} Gbps", t.gbps));
        let tp_delta = match (headline_tp, go_tp) {
            (Some(rt), Some(gt)) => fmt_delta(rt.gbps, gt.gbps, true),
            _ => "N/A".to_string(),
        };
        let go_lat_p50 = g.latency.as_ref().map(|l| l.p50_us);
        let go_lat_p99 = g.latency.as_ref().map(|l| l.p99_us);
        let go_cr = g.conn_rate.as_ref().map(|c| c.connections_per_sec);
        let delta = |a: Option<f64>, b: Option<f64>, hib: bool| match (a, b) {
            (Some(a), Some(b)) => fmt_delta(a, b, hib),
            _ => "N/A".to_string(),
        };

        format!(
            r#"## Benchmarks

Measured on {}, loopback (`127.0.0.1`). Both binaries use identical config (`mode: direct`, SOCKS5 listener). Run with `bash bench.sh`.

{}

| Metric | mihomo (Go) | meow-rs | Delta |
|--------|-------------|-------------|-------|
| Binary size (stripped) | {} | {} | {} |
| RSS idle | {} | {} | {} |
| RSS under load | {} | {} | {} |
| TCP throughput (64 MB) | {} | {} | {} |
| Latency p50 | {} | {} | {} |
| Latency p99 | {} | {} | {} |
| Connections/sec | {} | {} | {} |
{}"#,
            report.meta.platform,
            fmt_meta_line(&report.meta),
            fmt_bytes(g.binary_size_bytes),
            fmt_bytes(r.binary_size_bytes),
            fmt_delta(
                r.binary_size_bytes as f64,
                g.binary_size_bytes as f64,
                false
            ),
            fmt_bytes(g.rss_idle_bytes),
            fmt_bytes(r.rss_idle_bytes),
            fmt_delta(r.rss_idle_bytes as f64, g.rss_idle_bytes as f64, false),
            fmt_bytes(g.rss_load_bytes),
            fmt_bytes(r.rss_load_bytes),
            fmt_delta(r.rss_load_bytes as f64, g.rss_load_bytes as f64, false),
            go_tp_str,
            rust_tp_str,
            tp_delta,
            us(go_lat_p50),
            us(lat_p50),
            delta(lat_p50, go_lat_p50, false),
            us(go_lat_p99),
            us(lat_p99),
            delta(lat_p99, go_lat_p99, false),
            num(go_cr),
            num(cr),
            delta(cr, go_cr, true),
            fmt_dns_rows(r.dns.as_ref(), g.dns.as_ref()),
        )
    } else {
        // Rust-only results
        format!(
            r#"## Benchmarks

Measured on {}, loopback (`127.0.0.1`). Config: `mode: direct`, SOCKS5 listener. Run with `bash bench.sh`.

{}

| Metric | meow-rs |
|--------|-------------|
| Binary size (stripped) | {} |
| RSS idle | {} |
| RSS under load | {} |
| TCP throughput (64 MB) | {} |
| Latency p50 | {} |
| Latency p99 | {} |
| Connections/sec | {} |
{}"#,
            report.meta.platform,
            fmt_meta_line(&report.meta),
            fmt_bytes(r.binary_size_bytes),
            fmt_bytes(r.rss_idle_bytes),
            fmt_bytes(r.rss_load_bytes),
            rust_tp_str,
            us(lat_p50),
            us(lat_p99),
            num(cr),
            fmt_dns_rows_rust_only(r.dns.as_ref()),
        )
    }
}
