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
4. For [release-plz](#release-steps-release-plz), either:
   - **(preferred)** add a **`RELEASE_PLZ_TOKEN`** Actions secret: a GitHub App
     installation token or a fine-grained PAT on this repo with *Contents: read
     & write* and *Pull requests: read & write*. The release PR is then opened
     by that identity, so CI runs on it like on any other PR; or
   - enable *Settings → Actions → General → Allow GitHub Actions to create and
     approve pull requests*. The release PR is then opened by `GITHUB_TOKEN`,
     and GitHub runs **no CI on it** until a human pushes to the branch (the
     CHANGELOG cut below does that).

   Without either, the `release-pr` job fails and releases fall back to the
   [manual steps](#manual-release-steps).

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

## Release steps (release-plz)

[`release-plz.yml`](../.github/workflows/release-plz.yml) with
[`release-plz.toml`](../release-plz.toml) automates the version bump and the
tag. It does **not** write the changelog, publish crates or build binaries
itself: `CHANGELOG.md` stays hand-curated, and the existing
[`publish.yml`](../.github/workflows/publish.yml) and
[`release.yml`](../.github/workflows/release.yml) do the publishing.

1. **Every push to `main`** refreshes a standing PR titled
   `chore(release): X.Y.Z` (branch `release-plz-*`, label `release`). It bumps
   `[workspace.package] version`, the `[workspace.dependencies]` pins,
   `meow-anytls` (its own `version`, kept in the same `version_group`) and
   `Cargo.lock`. The version comes from the conventional commits since the
   last release: `feat` → minor, `fix`/`perf` → patch, `!`/`BREAKING CHANGE` →
   minor while we are on 0.x. To pick a different version, edit the PR (see
   step 3).

2. **Green CI on `main`.** The release does not run the test suite; make sure
   [`test.yml`](../.github/workflows/test.yml) is passing on `main`.

3. **Cut the changelog on the release PR branch**, as the last thing before
   merging: rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, add a fresh
   empty `## [Unreleased]` above it, and push that commit to the `release-plz-*`
   branch. The `CHANGELOG has the release section` check on the PR stays red
   until the section exists. Your push also starts the normal CI on the PR.

   > [!NOTE]
   > If anything else merges to `main` after your push, release-plz closes
   > the PR (it never force-pushes over human commits) and opens a new one.
   > Redo the cut on the new PR.

4. **Squash-merge the release PR** once CI is green. On that merge commit the
   `release` job pushes the single `vX.Y.Z` tag (on `meow-app`; no per-crate
   tags), then calls `publish.yml` (crates.io) and `release.yml` (binaries,
   OpenWrt packages, GitHub release). Pushes to `main` that did not come from
   a release PR never tag anything.

5. **Post-release.** Check the *Release-plz* run, then
   `cargo info meow-app` and the GitHub release.

Because the tag is pushed with `GITHUB_TOKEN`, GitHub does not start the
`push: tags` runs of `publish.yml` / `release.yml` as well; the calls in
step 4 are the only ones. If one of them fails, re-run that job from the
*Release-plz* run (`publish.yml` skips crates already on the registry).

## Manual release steps

The fallback when release-plz is not set up or a release needs special handling.
Do not mix the two for one version: if you cut a release by hand, close the
open release-plz PR afterwards (it is regenerated on the next push).

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
- **Upstream only.** Jobs are gated on `github.repository == 'meow-rs/meow-rs'`.
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
