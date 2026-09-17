use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use meow_trie::DomainTrie;

fn build_trie(n: usize) -> DomainTrie<u32> {
    let mut trie = DomainTrie::new();
    for i in 0..n {
        // Mix of exact, wildcard, and dot-wildcard entries
        match i % 3 {
            0 => trie.insert(&format!("host{}.example{}.com", i, i / 10), i as u32),
            1 => trie.insert(&format!("*.suffix{}.net", i / 10), i as u32),
            _ => trie.insert(&format!("+.domain{}.org", i / 10), i as u32),
        };
    }
    trie
}

fn bench_trie_search(c: &mut Criterion) {
    let mut group = c.benchmark_group("trie_search");

    for n in [100usize, 1_000, 10_000] {
        let trie = build_trie(n);

        // 50% hit, 50% miss
        let hit_domains: Vec<String> = (0..n)
            .step_by(2)
            .map(|i| format!("host{}.example{}.com", i, i / 10))
            .collect();
        let miss_domains: Vec<String> = (0..n)
            .step_by(2)
            .map(|i| format!("notfound{}.example{}.com", i, i / 10))
            .collect();

        group.bench_with_input(BenchmarkId::new("hit", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let result = trie.search(black_box(&hit_domains[idx % hit_domains.len()]));
                idx = idx.wrapping_add(1);
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("miss", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let result = trie.search(black_box(&miss_domains[idx % miss_domains.len()]));
                idx = idx.wrapping_add(1);
                black_box(result)
            });
        });

        let mut sealed = build_trie(n);
        sealed.seal();

        group.bench_with_input(BenchmarkId::new("sealed_hit", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let result = sealed.search(black_box(&hit_domains[idx % hit_domains.len()]));
                idx = idx.wrapping_add(1);
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("sealed_miss", n), &n, |b, _| {
            let mut idx = 0usize;
            b.iter(|| {
                let result = sealed.search(black_box(&miss_domains[idx % miss_domains.len()]));
                idx = idx.wrapping_add(1);
                black_box(result)
            });
        });

        group.bench_with_input(BenchmarkId::new("seal", n), &n, |b, _| {
            b.iter(|| {
                let mut t = build_trie(black_box(n));
                t.seal();
                black_box(t)
            });
        });

        group.bench_with_input(BenchmarkId::new("insert", n), &n, |b, _| {
            b.iter(|| {
                let mut t = DomainTrie::new();
                for i in 0..black_box(n) {
                    t.insert(&format!("host{i}.example.com"), i as u32);
                }
                black_box(t)
            });
        });
    }

    group.finish();
}

criterion_group!(benches, bench_trie_search);
criterion_main!(benches);
