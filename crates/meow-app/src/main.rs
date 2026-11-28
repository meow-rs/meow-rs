// dhat heap profiling — only active when compiled with --features dhat-heap.
// The profiler writes dh_out.json on process exit; parse with dhat-viewer.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// mimalloc global allocator — always on for musl targets (where the stock
// allocator retains freed pages under periodic churn — health probes,
// provider rebuilds — and RSS ratchets upward over long uptimes); opt-in
// elsewhere via --features alloc-mimalloc. The cfg mirrors the split
// target-gated deps in Cargo.toml: musl carries the dep unconditionally,
// other linux/android targets only under the feature (RFC 2957 — the
// feature alone never activates an inactive platform dep).
#[cfg(all(
    not(feature = "dhat-heap"),
    any(target_os = "linux", target_os = "android"),
    any(feature = "alloc-mimalloc", target_env = "musl")
))]
#[global_allocator]
static ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() -> anyhow::Result<()> {
    meow_app::run_cli()
}
