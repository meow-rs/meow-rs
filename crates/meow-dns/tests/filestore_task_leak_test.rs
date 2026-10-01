//! Regression test: `fakeip::FileStore` must abort its background flush task
//! on drop, not leak it.
//!
//! `FileStore::open` spawns a debounce-flush task that parks on
//! `notify.notified().await` and holds `Arc` clones of the store's
//! `state`/`dirty`/`notify`. Before the fix the `JoinHandle` was discarded and
//! `Drop for FileStore` did not abort it, so every dropped store (e.g. once per
//! fake-ip config reload) leaked one detached task plus its snapshot —
//! unbounded task + heap growth over a long-running daemon. The fix stores the
//! handle and `abort()`s it in `Drop` (mirroring the UDP NAT sweeper's
//! self-exit at crates/meow-tunnel/src/udp.rs:71).
//!
//! This test opens and drops many `FileStore`s and asserts the runtime's
//! alive-task count returns to baseline. It FAILS if the abort-on-drop
//! regresses.

use std::time::{Duration, Instant};

use meow_dns::fakeip::FileStore;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn filestore_does_not_leak_flush_task_on_drop() {
    let handle = tokio::runtime::Handle::current();
    let tmp = std::env::temp_dir();

    // Baseline: poll the alive-task count until two consecutive reads
    // agree — a fixed settle is a scheduling bet, and an inflated
    // baseline would hide leaks (issue #641).
    let baseline = {
        let deadline = Instant::now() + Duration::from_secs(5);
        let mut prev = handle.metrics().num_alive_tasks();
        loop {
            tokio::time::sleep(Duration::from_millis(10)).await;
            let cur = handle.metrics().num_alive_tasks();
            if cur == prev || Instant::now() >= deadline {
                break cur;
            }
            prev = cur;
        }
    };

    const N: usize = 50;
    for i in 0..N {
        let path = tmp.join(format!("meow-fakeip-leak-{}-{i}.json", std::process::id()));
        let store = FileStore::open(&path).expect("open FileStore");
        // Each open() spawned a flush task; dropping the store should reclaim it.
        drop(store);
        let _ = std::fs::remove_file(&path);
    }

    // Poll until the runtime reaps the abort-on-drop cancellations
    // instead of betting on a fixed settle (issue #641). The deadline is
    // a std Instant on purpose — it stays real-time even if this test
    // were ever switched to `start_paused`.
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut after = handle.metrics().num_alive_tasks();
    while after > baseline + 2 && Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(10)).await;
        after = handle.metrics().num_alive_tasks();
    }
    let leaked = after.saturating_sub(baseline);

    println!(
        "FileStore flush tasks: baseline_alive_tasks={baseline} after_{N}_open+drop={after} \
         leaked={leaked}  (must be ~0 — the flush task is aborted on drop)"
    );

    assert!(
        leaked <= 2,
        "FileStore leaked {leaked} background flush tasks after opening and dropping {N} stores \
         — Drop for FileStore must abort the task spawned in spawn_flush_task. Each leaked task \
         also pins an Arc<Mutex<PersistedSnapshot>>."
    );
}
