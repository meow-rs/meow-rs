# TCP throughput follow-up (#746)

Issue [#746](https://github.com/meow-rs/meow-rs/issues/746) asks why the
0.21.2 README snapshot puts 1 MiB × 10 about 2% behind mihomo and
4 KiB × 10,000 about 1% behind. Repeated comparisons of current 0.22.0
initially changed the ranking between runs. Investigation found a source
of large timing outliers in the benchmark's own sockets.

## Fix the measurement endpoints

The SOCKS load generator and TCP echo server left Nagle enabled. Packet
capture on macOS loopback showed stalled echo connections: a 52-byte tail
segment was retransmitted after roughly 234 ms, followed by the remaining
echo bytes. The same pattern appeared with meow and mihomo. Such a pause
is much larger than the normal duration of a 1 MiB transfer and should not
be interpreted as time spent processing packets in the proxy.

The harness now enables `TCP_NODELAY` on its client sockets and accepted
echo-server sockets. Errors propagate from the client or close the echo
connection, rather than silently using a different socket configuration.
No application socket options, relay buffers, or release profile change.

A diagnostic run used 120 interleaved rounds per proxy, with ten 1 MiB
transfers per round (3,600 transfers in each experiment). It included the
original meow binary, an experimental meow build with proxy-side
TCP_NODELAY, and mihomo. The same harness socket policy applied to all.

| Transfers taking over 15 ms | Original meow | Proxy-NODELAY experiment | mihomo | Total |
|---|---:|---:|---:|---:|
| Original harness | 19 | 11 | 43 | 73 |
| Harness TCP_NODELAY | 1 | 0 | 0 | 1 |

This substantially reduces the observed transport stalls; it does not
remove ordinary scheduler or host-load noise. Enabling TCP_NODELAY only
inside meow did not eliminate the harness stalls, and that application
experiment is not retained. Full diagnostic samples and slow-transfer
timings are in the [raw data](tcp-throughput-746.json).

## Measurement integrity and comparison method

The large-transfer benchmark also now rejects incomplete echoes instead
of reporting throughput after early EOF. A regression test has a SOCKS
server accept the entire upload but return only half of the echo.

The new [`throughput_interleaved`](../../crates/meow-bench/examples/throughput_interleaved.rs)
example reuses the normal echo server, SOCKS client, and throughput
functions. It accepts two or three running proxies, warms each once, and
rotates execution order. Three proxies use all six permutations; two use
both orders. Only a complete run produces the final JSON; transfer errors
propagate as a nonzero exit. Each sample records its round, proxy index,
workload, byte count, elapsed time, and throughput. No slow samples are
excluded. Payloads, connection counts, and timed regions remain:

- **4 KiB × 10,000:** one connection, 10,000 sequential echo round trips.
- **1 MiB × 10:** ten connections, each concurrently writing and reading
  1 MiB. SOCKS negotiation is outside each timed interval.
- **64 MiB × 1:** one concurrent upload/echo transfer.

## Host and results

Apple M4, macOS 27.0, Rust 1.98.1; meow 0.22.0 application source
`3c27aca`; mihomo v1.19.31 darwin arm64, Go 1.26.8. Both proxies use
`config-bench.yaml`, changing only the listening port. This is a shared
Mac under its existing load; no builds or tests from this investigation
run during measurements. It differs from the README's M4 Pro host.

The final comparison consists of three complete 60-round trials using the
corrected harness, with fresh proxy processes for each trial. The unchanged
application binary has the same SHA-256 as the original baseline; hashes,
every sample, and per-trial summaries are recorded in the raw data.

The summary is the median of the three per-trial medians (Gbps):

| Workload | meow | mihomo | Relative difference |
|---|---:|---:|---:|
| 4 KiB × 10,000 | 0.782 | 0.671 | +16.4% |
| 1 MiB × 10 | 11.451 | 11.361 | +0.8% |
| 64 MiB × 1 | 14.033 | 15.778 | −11.1% |

The two issue workloads meet parity in the aggregate comparison. The
1 MiB result is effectively tied, rather than a demonstrated speedup:
individual trial differences range from +3.4% to −1.8%. The 64 MiB
workload remains slower and is outside the two metrics requested in #746.
Per-trial medians for the issue workloads make the variation explicit:

| Trial | meow 4 KiB | mihomo 4 KiB | meow 1 MiB | mihomo 1 MiB |
|---|---:|---:|---:|---:|
| 1 | 0.763 | 0.651 | 11.451 | 11.076 |
| 2 | 0.782 | 0.671 | 11.361 | 11.361 |
| 3 | 0.842 | 0.700 | 11.672 | 11.882 |

This resolves the reported small deficits in a repeated comparison with
corrected measurement endpoints. It is **not** an application speedup:
the meow binary is unchanged, and the earlier runtime candidates were
rejected. Historical numbers from the uncorrected harness are not directly
comparable with the corrected results.

These are local loopback measurements, not a guarantee for every platform,
protocol, workload, or host load. The README's older table remains labeled
with its original versions and host; its single snapshot should not be
used to infer a persistent 1–2% runtime bottleneck.

## Rejected experiments and validation

The raw data also retain earlier comparisons with the uncorrected harness.
They are separate trials, not pooled with the corrected measurements.
Runtime experiments—earlier bulk-buffer promotion, proxy TCP_NODELAY,
selective compiler optimization, and cached cancellation registration—did
not establish repeatable improvements in both issue workloads. Global
release optimization also exceeded the minimal router's 8 MiB size gate.
None of those changes is retained.

Validation passed:

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets -- -D warnings`
- `cargo test --lib` (2,241 tests)
- `cargo test -p meow-bench` (truncated-echo regression)
- `cargo build --release -p meow-app -p meow-bench`
- Three complete 60-round comparisons, with exact byte counts in all samples.

At the recorded benchmark source revision `3c27aca`, the rebuilt `meow`
binary matched the original benchmarked application
SHA-256 (`a430c7af6da67604c03991d62723da3c4527719c4992e8ef1cf60e10f32ca443`).
Only harness behavior changes; no runtime speedup is attributed to this patch.

## Reproduce

Build the application and example:

```bash
cargo build --release -p meow-app -p meow-bench
cargo build --release -p meow-bench --example throughput_interleaved
mkdir -p target/bench/746
```

Set `MIHOMO` to the v1.19.31 binary, then run in one shell:

```bash
sed 's/mixed-port: 17890/mixed-port: 18390/' config-bench.yaml > target/bench/746/meow.yaml
sed 's/mixed-port: 17890/mixed-port: 18391/' config-bench.yaml > target/bench/746/mihomo.yaml
for trial in 1 2 3; do
  (
    set -e
    target/release/meow -f target/bench/746/meow.yaml > "target/bench/746/meow-$trial.log" 2>&1 &
    meow_pid=$!
    "$MIHOMO" -f target/bench/746/mihomo.yaml > "target/bench/746/mihomo-$trial.log" 2>&1 &
    mihomo_pid=$!
    trap 'kill "$meow_pid" "$mihomo_pid" 2>/dev/null; wait' EXIT
    sleep 2
    target/release/examples/throughput_interleaved \
      127.0.0.1:18390 127.0.0.1:18391 --rounds 60 \
      > "target/bench/746/interleaved-$trial.json" \
      2> "target/bench/746/interleaved-$trial.log"
  ) || exit "$?"
done
```

Variant 0 is meow and variant 1 is mihomo. For a three-way experiment,
pass a third listening address; multiples of six rounds balance all orders.
