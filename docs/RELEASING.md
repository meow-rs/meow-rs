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

A release is two clicks: dispatch **Prepare release**, then merge the PR it
prepares. Tagging, crates.io and the GitHub Release follow from the merge. No
secret beyond `CARGO_REGISTRY_TOKEN` is involved.

1. **Green CI on `main`, complete `[Unreleased]`.** The release does not run
   the test suite; make sure [`test.yml`](../.github/workflows/test.yml) is
   passing. The `CHANGELOG.md` `[Unreleased]` entries become the release notes
   as written (GitHub's generated PR list is appended below them), so curate
   them first — the prepare step refuses an empty `[Unreleased]`.

2. **Prepare.** `Actions → Prepare release → Run workflow` on `main`
   ([`prepare-release.yml`](../.github/workflows/prepare-release.yml)). Leave
   **version** empty to infer it from the conventional commits since the last
   tag — a breaking change (`type!:` / `BREAKING CHANGE:`) or any `feat` bumps
   the minor while we are on 0.x, anything else the patch — or enter `X.Y.Z`.
   [`scripts/release/prepare.sh`](../scripts/release/prepare.sh) then:
   - bumps `[workspace.package] version` and every internal
     `version = "…"` pin (root `[workspace.dependencies]`, `lwip`, and the
     vendored `crates/meow-anytls`, which spells its version out);
   - runs `cargo update -w` to move the workspace members in `Cargo.lock`;
   - opens `## [X.Y.Z] - YYYY-MM-DD` directly under `## [Unreleased]`, which
     stays as an empty heading.

   That `cargo update -w` can move `boring`, `boring-sys` or `tokio-boring`
   (they move together — see the note in `Cargo.toml`). If it does, check the
   `armv7-unknown-linux-musleabihf` leg's patch target before tagging: that leg
   sed-patches `boring`'s vendored `src/x509/verify.rs`
   ([`scripts/build-armv7-musl.sh`](../scripts/build-armv7-musl.sh)) and fails
   the leg — blocking the whole release — when the patched line is gone. The
   sources are unpacked by then (`cargo check` below does it), so:

   ```bash
   ver=$(awk '/^\[\[package\]\]/{pkg=""} /^name = "boring"$/{pkg="boring"} pkg=="boring" && /^version = /{gsub(/"/,"",$3); print $3; exit}' Cargo.lock)
   grep -l 'X509_VERIFY_PARAM_set_time(self\.as_ptr(), time)' \
     "${CARGO_HOME:-$HOME/.cargo}"/registry/src/*/boring-"$ver"/src/x509/verify.rs 2>/dev/null
   ```

   Expected: prints the vendored `verify.rs` path. Empty output means the leg
   will fail on the release run — update the script or revert the bump first.
   The build script now checks the locked version itself and stops with that
   message before the compile, so a moved call is reported as a patch problem
   rather than as a type mismatch inside `boring`.
   For the definitive check, run the leg itself, with the same digest-pinned
   image `build.yml` uses:

   ```bash
   cargo check --workspace
   docker run --rm -v "$PWD:/src" -w /src \
     ghcr.io/rust-cross/rust-musl-cross:armv7-musleabihf-amd64@sha256:c2603200841eac1a6681d7beef44816c9954b0f59952ae7ae96652788287e16f \
     bash scripts/build-armv7-musl.sh
   ```

   The workflow commits that as `chore(release): X.Y.Z` and pushes branch
   `release/vX.Y.Z`. The same script works locally
   (`scripts/release/prepare.sh [X.Y.Z]` in a clean checkout with tags).

3. **Open and merge the PR.** The run summary has an *Open the release PR*
   link (a prefilled compare page) and the cut notes. The workflow cannot open
   the PR itself: this repo does not let `GITHUB_TOKEN` create pull requests,
   and a PR opened by `GITHUB_TOKEN` would not trigger `test.yml`. Review the
   version and the notes (push fixes to the branch if needed), wait for CI,
   squash-merge.

4. **Tag + publish (automatic).** The merge changes the workspace version on
   `main`, which triggers [`tag-release.yml`](../.github/workflows/tag-release.yml).
   It checks that `CHANGELOG.md` has the `## [X.Y.Z]` section, creates the
   annotated tag `vX.Y.Z` on the merge commit, and then calls:
   - [`publish.yml`](../.github/workflows/publish.yml) — verifies the tag
     matches the workspace version and publishes all 13 crates in order;
   - [`release.yml`](../.github/workflows/release.yml) — builds the binaries
     and OpenWrt packages and publishes the GitHub Release, with the
     `CHANGELOG.md` section as its notes.

   A tag pushed with `GITHUB_TOKEN` triggers no workflows, so these two run
   from `tag-release.yml` instead of from the tag push — exactly once. If a
   job fails, fix the cause and use **Re-run failed jobs**; re-running *all*
   jobs sees that the tag exists and does nothing. `publish.yml` skips
   versions already on the registry, so a partial publish resumes.

5. **Post-release.** Verify `cargo install meow-app` (or `cargo info
   meow-app`) and the Release page.

`crate_publish_metadata_test` (part of CI) asserts that every workspace crate
is at one version and every internal dependency pins it, so a hand-edited bump
that misses a pin fails the release PR.

### Tagging by hand

The original flow still works and is the fallback when `tag-release.yml` did
not tag (an Actions outage, the workflow disabled, or a bump it refused
because its CHANGELOG section is missing): push the tag yourself from the
merged release commit.

```bash
git fetch origin && git checkout --detach <merged chore(release) commit>
git tag -a v0.15.1 -m v0.15.1
git push origin v0.15.1
```

A tag pushed by a person (not `GITHUB_TOKEN`) triggers `publish.yml` and
`release.yml` directly. Whichever of the two paths creates the tag first
wins; the other sees the tag and stands down.

### Rehearsal

- **crates.io:** `Actions → Publish to crates.io → Run workflow` with
  **dry-run** left ticked packages and verifies all 13 crates without
  uploading.
- **Binaries:** `Actions → Release → Run workflow` with a tag builds the full
  artifact matrix without publishing a Release.

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

## Publishing locally

If the publish workflow is unavailable, publish locally (logged in via `cargo login`):

```bash
for c in meow-common meow-trie meow-anytls meow-lwip meow-transport \
         meow-rules meow-dns meow-proxy \
         meow-config meow-tunnel meow-listener meow-api \
         meow-app; do
  cargo publish -p "$c" || break   # waits for index propagation between crates
done
```
