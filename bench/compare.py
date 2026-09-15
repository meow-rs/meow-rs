#!/usr/bin/env python3
"""
Compare a new benchmark run against a baseline and flag regressions.

Usage:
    python3 bench/compare.py <baseline> <current.json> [--threshold 0.05]

`baseline` may be a single results.json, or a directory of downloaded
run artifacts (searched recursively for *.json). A directory collapses
into a synthetic baseline of per-metric medians — far more robust on
noisy shared CI runners than comparing against any single day.

Exit codes:
    0  no regressions beyond threshold
    1  one or more metrics regressed beyond threshold
"""

import json
import statistics
import sys
import argparse
from pathlib import Path


METRICS = [
    # (path_in_rust_obj, label, higher_is_better)
    ("conn_rate.connections_per_sec", "conn_rate (conns/s)", True),
    ("latency.p50_us",                "latency p50 (µs)",    False),
    ("latency.p99_us",                "latency p99 (µs)",    False),
    ("rss_idle_bytes",                "RSS idle (bytes)",     False),
    ("rss_load_bytes",                "RSS load (bytes)",     False),
]

THROUGHPUT_LABEL = "64 MB x 1"


def get_nested(obj, path):
    for key in path.split("."):
        if not isinstance(obj, dict):
            return None
        obj = obj.get(key)
    return obj


def set_nested(obj, path, value):
    keys = path.split(".")
    for key in keys[:-1]:
        obj = obj.setdefault(key, {})
    obj[keys[-1]] = value


def get_throughput(rust_obj, label):
    for t in rust_obj.get("throughput") or []:
        if t.get("label", "").startswith(label):
            return t.get("gbps")
    return None


def load_baseline_rust(baseline, current_path=None):
    """Return the `rust` object to compare `current` against."""
    p = Path(baseline)
    if not p.is_dir():
        with open(p) as f:
            return json.load(f).get("rust", {})

    current_resolved = Path(current_path).resolve() if current_path else None
    rusts = []
    files = []
    for f in sorted(p.rglob("*.json")):
        # Never let the current run become part of its own baseline —
        # passing e.g. `target/bench` as the dir would otherwise dilute
        # the regression signal with the very numbers being judged.
        if current_resolved is not None and f.resolve() == current_resolved:
            continue
        try:
            with open(f) as fh:
                doc = json.load(fh)
        except (OSError, ValueError):
            continue
        if not isinstance(doc, dict):
            continue
        rust = doc.get("rust")
        if isinstance(rust, dict) and rust:
            rusts.append(rust)
            files.append(f)

    if not rusts:
        return {}

    print(f"baseline: per-metric median over {len(rusts)} previous run(s)")
    for f in files:
        print(f"  - {f}")

    base = {}
    for path, _label, _hib in METRICS:
        vals = [
            v
            for o in rusts
            if isinstance(v := get_nested(o, path), (int, float))
        ]
        if vals:
            set_nested(base, path, statistics.median(vals))

    tps = [
        t
        for o in rusts
        if isinstance(t := get_throughput(o, THROUGHPUT_LABEL), (int, float))
    ]
    base["throughput"] = (
        [{"label": THROUGHPUT_LABEL, "gbps": statistics.median(tps)}] if tps else []
    )
    return base


def compare(baseline_path, current_path, threshold):
    base_rust = load_baseline_rust(baseline_path, current_path)
    with open(current_path) as f:
        current = json.load(f)
    curr_rust = current.get("rust", {})

    regressions = []
    rows = []

    for path, label, higher_is_better in METRICS:
        base_val = get_nested(base_rust, path)
        curr_val = get_nested(curr_rust, path)
        if base_val is None or curr_val is None or base_val == 0:
            continue

        delta = (curr_val - base_val) / abs(base_val)
        regressed = (delta < -threshold) if higher_is_better else (delta > threshold)
        flag = "REGRESSED" if regressed else "ok"
        rows.append((label, base_val, curr_val, delta * 100, flag))
        if regressed:
            regressions.append(label)

    # Throughput
    base_tp = get_throughput(base_rust, THROUGHPUT_LABEL)
    curr_tp = get_throughput(curr_rust, THROUGHPUT_LABEL)
    if base_tp and curr_tp and base_tp != 0:
        delta = (curr_tp - base_tp) / abs(base_tp)
        regressed = delta < -threshold
        flag = "REGRESSED" if regressed else "ok"
        rows.append((f"throughput {THROUGHPUT_LABEL} (Gbps)", base_tp, curr_tp, delta * 100, flag))
        if regressed:
            regressions.append(f"throughput {THROUGHPUT_LABEL}")

    # Print table
    print(f"\n{'Metric':<35} {'Baseline':>12} {'Current':>12} {'Delta':>8}  Status")
    print("-" * 80)
    for label, base, curr, pct, flag in rows:
        marker = " <-- REGRESSION" if flag == "REGRESSED" else ""
        print(f"{label:<35} {base:>12.2f} {curr:>12.2f} {pct:>+7.1f}%  {flag}{marker}")

    print()
    if not rows:
        print(
            "WARNING: no comparable metrics — nothing was compared",
            file=sys.stderr,
        )
    if regressions:
        print(f"FAIL: {len(regressions)} regression(s) beyond {threshold*100:.0f}% threshold:")
        for r in regressions:
            print(f"  - {r}")
        sys.exit(1)
    else:
        print(f"PASS: no regressions beyond {threshold*100:.0f}% threshold.")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline", help="Path to a baseline JSON, or a directory of run artifacts")
    parser.add_argument("current", help="Path to current run JSON")
    parser.add_argument("--threshold", type=float, default=0.05,
                        help="Regression threshold as a fraction (default: 0.05 = 5%%)")
    args = parser.parse_args()
    compare(args.baseline, args.current, args.threshold)


if __name__ == "__main__":
    main()
