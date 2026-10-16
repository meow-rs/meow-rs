# Releasing meow-rs

meow-rs ships as **13 crates** published together to [crates.io](https://crates.io)
at a single workspace version. This is the checklist for cutting a release.

> [!IMPORTANT]
> **crates.io is append-only.** A published version can never be deleted, only
> *yanked*. You can never re-publish the same version number. Every release must
> bump the version. `0.15.0` is already taken — the next release is `0.15.1` (or
> `0.16.0`).

## One-time setup

1. Create a crates.io API token at <https://crates.io/settings/tokens> with the
   **publish-new** and **publish-update** scopes.
2. Add it to the repo as the **`CARGO_REGISTRY_TOKEN`** Actions secret
   (`Settings → Secrets and variables → Actions`). The
   [`publish.yml`](../.github/workflows/publish.yml) workflow reads it.
3. Confirm you own all 13 crate names on crates.io.

## The crates & publish order

All crates share the workspace version (`[workspace.package] version` in the root
`Cargo.toml`). `meow-bench` is **not** published. The publish order is dictated by
dependencies — including **dev-dependencies**, which crates.io validates at publish
time (e.g. `meow-tunnel` dev-depends on `meow-config`, so config goes first):

```
meow-common  meow-trie  meow-anytls  meow-lwip  meow-transport   (leaves)
meow-rules   meow-dns                        (→ common, trie)
meow-proxy                                   (→ common, dns, transport, anytls)
meow-config                                  (→ common, trie, dns, rules, proxy)
meow-tunnel                                  (→ …, + dev-dep on config)
meow-listener  meow-api                      (→ tunnel, config)
meow-app                                     (→ everything)
```

## Release steps

1. **Green CI on `main`.** The release does not run the test suite; make sure
   [`test.yml`](../.github/workflows/test.yml) is passing first.

2. **Bump the version.** Edit `[workspace.package] version` in the root
   `Cargo.toml`. Because the internal deps are pinned to that version (e.g.
   `meow-common = { path = "…", version = "0.15.0" }`), bump those entries in
   `[workspace.dependencies]` to match the new version too.

3. **Refresh the lockfile.**
   ```bash
   cargo update -w        # re-resolve workspace members to the new version
   cargo check --workspace
   ```
   If `cargo update -w` moved `boring`, `boring-sys`, or `tokio-boring`
   (they must move together — see the note in `Cargo.toml`), the
   `armv7-unknown-linux-musleabihf` release leg may break: it sed-patches
   `boring`'s vendored `src/x509/verify.rs`
   (`scripts/build-armv7-musl.sh`) and fails the leg — which blocks the
   whole release — when the patched line is gone. `cargo check` above
   already unpacked the locked sources, so verify the patch target before
   tagging:
   ```bash
   ver=$(grep -A1 '^name = "boring"$' Cargo.lock | sed -n 's/^version = "\(.*\)"/\1/p')
   grep -l 'X509_VERIFY_PARAM_set_time(self\.as_ptr(), time)' \
     "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/boring-"$ver"/src/x509/verify.rs 2>/dev/null
   ```
   Expected: prints the vendored `verify.rs` path. Empty output means the
   leg will fail on the release run — update the script or revert the
   bump first. For the definitive check, run the leg itself (same image
   as `build.yml`'s `toolchain:` key; use its digest-pinned form for
   exact CI parity):
   ```bash
   docker run --rm -v "$PWD:/src" -w /src \
     ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf-amd64@sha256:c2603200841eac1a6681d7beef44816c9954b0f59952ae7ae96652788287e16f \
     bash scripts/build-armv7-musl.sh
   ```

4. **PR & merge to `main`** with the version bump (e.g. `chore(release): 0.15.1`).

5. **Tag and push** from the merged commit on `main`:
   ```bash
   git checkout main && git pull --ff-only
   git tag v0.15.1
   git push origin v0.15.1
   ```
   The tag push triggers [`publish.yml`](../.github/workflows/publish.yml), which
   verifies the tag matches the workspace version and publishes all 13 crates in
   order. (The workflow is idempotent — a re-run skips versions already on the
   registry, so a partial release can resume.)

6. **Dry-run option.** To rehearse without uploading, run the workflow manually
   (`Actions → Publish to crates.io → Run workflow`) with **dry-run** left ticked.

7. **Post-release.**
   - Verify: `cargo install meow-app` (or `cargo info meow-app`).
   - Cut a GitHub Release for the tag with notes / prebuilt binaries.

## Alpha prereleases

[`alpha.yml`](../.github/workflows/alpha.yml) publishes a rolling GitHub
prerelease (tag `Prerelease-Alpha`, issue #565) on every push to `main` and on
manual dispatch. Docs/website/markdown-only pushes are skipped. Nothing here is
part of cutting a stable release; it needs no manual steps.

- **Shared build.** Both `release.yml` and `alpha.yml` call the reusable
  [`build.yml`](../.github/workflows/build.yml) (target matrix, packaging, OpenWrt
  ipks). Change targets/packaging there, once.
- **Assets.** `meow-alpha-<sha7>-<target>.{tar.gz,zip}` plus `.sha256`, and the
  OpenWrt `.ipk`s. Each run moves the tag to the built commit, uploads the new
  assets, then deletes stale ones. The release is `prerelease` and never
  `latest`; notes list the commit, build time and commits since the last `v*` tag.
- **Version.** `meow -v` prints `<version>-alpha+<sha7>`
  (`MEOW_VERSION_SUFFIX`, read by `crates/meow-app/build.rs`). `.ipk` versions are
  `<workspace version>-alpha.<YYYYMMDDHHMM>.<sha7>-1`: because `main` stays at the last
  released version between releases, this sorts above `<ver>-1` and below the next
  release under opkg's Debian-style ordering.
- **No cross-triggering.** `release.yml` and `publish.yml` fire only on `v*` tags;
  `Prerelease-Alpha` does not match, and tags pushed by `GITHUB_TOKEN` do not
  trigger workflows anyway. Never create a `v*` tag by hand for alphas.
- **Upstream only.** Jobs are gated on `github.repository == 'madeye/meow-rs'`.
- **Concurrency.** A newer push cancels an in-flight alpha run; the publish job also
  skips itself if `main` has already moved on.

## Rate limits

- **New crate names:** burst of ~5, then ~1 per 10 minutes. This only bit the
  *first* publish (0.15.0). It does **not** apply to new versions of existing
  crates.
- **New versions of existing crates:** a much higher limit, so a normal release
  publishes all 13 crates back-to-back without throttling.

## Forked dependencies

**crates.io forbids `git` dependencies in a published manifest — even optional,
non-default ones.** A `git =` entry anywhere in `[workspace.dependencies]` makes
every crate that reaches it unpublishable. This bit the `0.20.2` release: a git
pin on the `lwip` fork (added with TUN inbound, #326) aborted the publish job
after nine crates had already uploaded, stranding `meow-listener`, `meow-api`
and `meow-app` at `0.20.1`.

So a fork has to be **vendored in-tree** or **published to the registry** before
anything can depend on it:

| Fork | Route | Notes |
|------|-------|-------|
| `anytls-rs` | Vendored as `crates/meow-anytls` (lib name `anytls_rs`), published with the workspace | Upstream lacks `Stream::close()`. Opt-in via `meow-proxy`'s `anytls` feature. |
| `lwip` | Vendored as `crates/meow-lwip` (lib name `lwip`), published with the workspace at the shared version | Upstream `lwip` is **not** a substitute: the fork rewrites the Rust layer (single-owner core) and carries the `poll_next` UAF, `poll_flush` deadlock, FIN_WAIT_2 leak and livelock fixes. Required by `listener-tun`, which is in `meow-app`'s default `full` bundle. Only the files build.rs consumes are vendored (`old-src/`, `src/api/err.c`, `rust/`) — re-check that list when syncing a newer fork commit. `meow-lwip 0.3.15`, published once from the fork repo before vendoring, is superseded by the workspace-versioned releases. |

If you need a newer fork change, publish it to crates.io first, then bump the
version here — never point `[workspace.dependencies]` at a git rev.

## Manual fallback

If the workflow is unavailable, publish locally (logged in via `cargo login`):

```bash
for c in meow-common meow-trie meow-anytls meow-lwip meow-transport \
         meow-rules meow-dns meow-proxy \
         meow-config meow-tunnel meow-listener meow-api \
         meow-app; do
  cargo publish -p "$c" || break   # waits for index propagation between crates
done
```
