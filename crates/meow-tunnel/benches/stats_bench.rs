/// Global traffic-accounting benchmark (issue #340).
///
/// Guards the per-chunk relay accounting hot path: `record_upload` /
/// `record_download` run once per relayed chunk per direction, so any change
/// to `Statistics` byte counting must not regress them. Also covers the
/// cold paths (`sample_traffic` ticker, `snapshot` API reads) so moving work
/// off the hot path doesn't silently blow up the readers.
use criterion::{black_box, criterion_group, criterion_main, Criterion};
use meow_common::{ConnType, DnsMode, Metadata, Network};
use meow_tunnel::statistics::ConnCounters;
use meow_tunnel::{Statistics, Tunnel};
use std::sync::Arc;

fn bench_tunnel() -> Tunnel {
    Tunnel::new(Arc::new(meow_dns::Resolver::new(
        vec![],
        vec![],
        DnsMode::Normal,
        meow_trie::DomainTrie::new(),
        false,
        false,
    )))
}

fn bench_accounting(c: &mut Criterion) {
    let stats = Statistics::new();
    let counters = ConnCounters::default();

    // Hot path: per-chunk accounting (ConnCounters bump + global temp bump).
    c.bench_function("stats_record_upload_chunk", |b| {
        b.iter(|| stats.record_upload(black_box(&counters), black_box(16 * 1024)));
    });
    c.bench_function("stats_record_download_chunk", |b| {
        b.iter(|| stats.record_download(black_box(&counters), black_box(16 * 1024)));
    });

    // Cold path: once-per-second sampler tick (with traffic in flight so the
    // swap/accumulate arms are exercised).
    c.bench_function("stats_sample_traffic_tick", |b| {
        b.iter(|| {
            stats.add_upload(black_box(1024));
            stats.add_download(black_box(2048));
            stats.sample_traffic();
        });
    });

    // Cold path: API readers.
    c.bench_function("stats_live_totals_snapshot", |b| {
        b.iter(|| black_box(stats.snapshot()));
    });
    c.bench_function("stats_traffic_snapshot", |b| {
        b.iter(|| black_box(stats.traffic_snapshot()));
    });

    // Connection setup is a separate path from per-chunk accounting. Keep
    // both modes comparable as the tracking implementation evolves.
    let full = bench_tunnel();
    let headless = bench_tunnel();
    headless.statistics().set_headless();
    let metadata = Metadata {
        network: Network::Tcp,
        conn_type: ConnType::Inner,
        host: "example.com".into(),
        dst_port: 443,
        ..Default::default()
    };
    let direct = meow_proxy::DirectAdapter::new();
    // A rule targeting a group records the selected member too
    // (`["DIRECT", "Proxy"]`), so full-mode setup walks one unwrap hop.
    let group = meow_proxy::SelectorGroup::new(
        "Proxy",
        vec![Arc::new(meow_config::proxy_parser::WrappedProxy::new(
            Box::new(meow_proxy::DirectAdapter::new()),
        ))],
    );
    c.bench_function("stats_connection_setup_full", |b| {
        b.iter(|| {
            black_box(full.inner().tcp_admission().track_named(
                black_box(&metadata),
                "MATCH".into(),
                "".into(),
                &direct,
            ));
        });
    });
    c.bench_function("stats_connection_setup_full_group", |b| {
        b.iter(|| {
            black_box(full.inner().tcp_admission().track_named(
                black_box(&metadata),
                "MATCH".into(),
                "".into(),
                &group,
            ));
        });
    });
    c.bench_function("stats_connection_setup_headless", |b| {
        b.iter(|| {
            black_box(headless.inner().tcp_admission().track_named(
                black_box(&metadata),
                "MATCH".into(),
                "".into(),
                &direct,
            ));
        });
    });
}

criterion_group!(benches, bench_accounting);
criterion_main!(benches);
