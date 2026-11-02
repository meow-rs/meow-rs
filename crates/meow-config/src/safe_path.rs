//! Containment checks for config-supplied provider paths (issue #429).
//!
//! A `path:` on a rule- or proxy-provider is attacker-influenced whenever the
//! config document arrives over the REST API (`PUT /configs`), so every path
//! read or written on behalf of a provider must stay inside the provider
//! cache directory — mirroring mihomo's `C.Path.IsSafePath` guard.
//!
//! the check is lexical only, exactly like mihomo's. Symlinks
//! already present under the provider directory are followed: only the
//! administrator can create them (a config cannot), and OpenWrt front-ends
//! (router front ends) point provider dirs at tmpfs through such links.

use std::path::{Component, Path, PathBuf};
use tracing::warn;

/// Name of the escape-hatch environment variable, mirroring mihomo.
const SKIP_ENV: &str = "SKIP_SAFE_PATH_CHECK";

/// Mirror of mihomo's `SKIP_SAFE_PATH_CHECK` escape hatch: when the env var
/// holds a truthy value, containment failures are downgraded to a prominent
/// `warn!` and the out-of-root path is allowed.
///
/// mihomo parses the variable with Go's `strconv.ParseBool`
/// (`allowUnsafePath, _ := strconv.ParseBool(os.Getenv("SKIP_SAFE_PATH_CHECK"))`),
/// so exactly `1`/`t`/`T`/`true`/`TRUE`/`True` enable it; anything else —
/// including an unset or empty variable — keeps the check ON.
fn skip_safe_path_check() -> bool {
    std::env::var(SKIP_ENV).is_ok_and(|v| go_parse_bool_truthy(&v))
}

/// The truthy half of Go's `strconv.ParseBool` accepted values.
fn go_parse_bool_truthy(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

/// Resolve `requested` against `base` and require the result to stay inside
/// `base`.
///
/// Robust to `..` traversal (paths are lexically normalized before the prefix
/// check) and absolute paths (allowed only when they already point inside
/// `base`). Symlinks are not resolved (mihomo parity, see the module docs).
///
/// Escape hatch (mihomo parity): setting `SKIP_SAFE_PATH_CHECK=1` in the
/// environment downgrades a containment failure to a prominent `warn!` and
/// lets the out-of-root path through — a migration path for configs that
/// legitimately point providers outside the cache dir. It defaults OFF; with
/// the variable unset the containment guarantee from issue #429 is fully
/// intact.
///
/// Returns the normalized absolute path that callers must use for the actual
/// I/O, so the checked path and the opened path cannot diverge lexically.
pub(crate) fn resolve_contained(base: &Path, requested: &Path) -> Result<PathBuf, String> {
    resolve_contained_impl(base, requested, skip_safe_path_check())
}

fn resolve_contained_impl(
    base: &Path,
    requested: &Path,
    skip_check: bool,
) -> Result<PathBuf, String> {
    let abs_base = normalize_absolute(base)?;
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        abs_base.join(requested)
    };
    let abs_joined = normalize_absolute(&joined)?;
    if !abs_joined.starts_with(&abs_base) {
        if skip_check {
            warn_skip_active(requested, base, "");
            return Ok(abs_joined);
        }
        return Err(format!(
            "path '{}' escapes the provider directory '{}'",
            requested.display(),
            base.display()
        ));
    }
    Ok(abs_joined)
}

fn warn_skip_active(requested: &Path, base: &Path, how: &str) {
    warn!(
        "{SKIP_ENV} is set: allowing provider path '{}' that escapes the provider \
         directory '{}'{how} — the path-containment protection (issue #429) is DISABLED; \
         unset {SKIP_ENV} to restore it",
        requested.display(),
        base.display(),
    );
}

/// Make `path` absolute (against the current directory) and lexically fold
/// `.` / `..` components. A `..` at the root is dropped (as the OS would),
/// so an under-flowing traversal can never gain components.
fn normalize_absolute(path: &Path) -> Result<PathBuf, String> {
    let abs = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .map_err(|e| format!("cannot resolve current directory: {e}"))?
            .join(path)
    };
    let mut out = PathBuf::new();
    for comp in abs.components() {
        match comp {
            Component::Prefix(_) | Component::RootDir => out.push(comp),
            Component::CurDir => {}
            // `pop()` refuses to remove the root/prefix, so this saturates
            // at the filesystem root instead of underflowing.
            Component::ParentDir => {
                let _ = out.pop();
            }
            Component::Normal(c) => out.push(c),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relative_path_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained(dir.path(), Path::new("sub/rules.yaml")).unwrap();
        let base = normalize_absolute(dir.path()).unwrap();
        assert_eq!(got, base.join("sub").join("rules.yaml"));
    }

    #[test]
    fn absolute_path_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let inside = dir.path().join("rules.yaml");
        let got = resolve_contained(dir.path(), &inside).unwrap();
        assert_eq!(got, inside);
    }

    #[test]
    fn dotdot_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("../../etc/pwned")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn nested_dotdot_traversal_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("a/b/../../../evil")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn absolute_path_outside_base_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let err = resolve_contained(dir.path(), Path::new("/etc/cron.d/pwned")).unwrap_err();
        assert!(err.contains("escapes"), "unexpected: {err}");
    }

    #[test]
    fn dotdot_stays_inside_base_is_ok() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained(dir.path(), Path::new("sub/../rules.yaml")).unwrap();
        assert!(got.ends_with("rules.yaml"));
        assert!(!got.to_string_lossy().contains(".."));
    }

    #[cfg(unix)]
    #[test]
    fn symlink_under_base_is_followed() {
        // mihomo parity: an administrator's symlink (e.g. providers -> tmpfs)
        // is a lexically contained path and stays accepted.
        let outside = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("link")).unwrap();
        let got = resolve_contained(base.path(), Path::new("link/rules.yaml")).unwrap();
        assert!(
            got.ends_with("link/rules.yaml"),
            "unexpected: {}",
            got.display()
        );
    }

    // -- SKIP_SAFE_PATH_CHECK escape hatch (mihomo parity) ------------------
    //
    // The skip flag is injected as a bool so these tests cannot race on the
    // process-global environment; `skip_safe_path_check()` itself is covered
    // by the `go_parse_bool_truthy` table below plus the pass-through in
    // `resolve_contained`.

    #[test]
    fn escape_hatch_off_rejects_out_of_root_paths() {
        let dir = tempfile::tempdir().unwrap();
        for p in ["../../etc/pwned", "/etc/cron.d/pwned"] {
            let err = resolve_contained_impl(dir.path(), Path::new(p), false)
                .expect_err("skip=false must keep the containment guarantee");
            assert!(err.contains("escapes"), "path {p}: unexpected: {err}");
        }
    }

    #[test]
    fn escape_hatch_on_allows_out_of_root_paths_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained_impl(dir.path(), Path::new("/etc/cron.d/pwned"), true)
            .expect("skip=true must allow the out-of-root path");
        // `/etc/...` is root-relative rather than absolute on Windows (no
        // drive prefix), so the impl anchors it on the base's drive and the
        // result is `C:\etc\cron.d\pwned`. Assert on the properties that
        // matter on every platform: the requested path came back intact, and
        // it really does sit outside the base. Join the suffix so the
        // comparison is component-wise with native separators.
        assert!(
            got.ends_with(Path::new("etc").join("cron.d").join("pwned")),
            "unexpected: {}",
            got.display()
        );
        assert!(
            !got.starts_with(normalize_absolute(dir.path()).unwrap()),
            "must have escaped the base: {}",
            got.display()
        );
        // Traversal is still lexically normalized before being handed back.
        let got = resolve_contained_impl(dir.path(), Path::new("sub/../../outside"), true).unwrap();
        assert!(!got.to_string_lossy().contains(".."));
    }

    #[test]
    fn escape_hatch_env_parsing_matches_go_parse_bool() {
        for truthy in ["1", "t", "T", "true", "TRUE", "True"] {
            assert!(go_parse_bool_truthy(truthy), "{truthy} must enable");
        }
        for falsy in ["", "0", "false", "f", "yes", "on", "2", " true", "true "] {
            assert!(!go_parse_bool_truthy(falsy), "{falsy:?} must NOT enable");
        }
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_base_still_contains_its_own_files() {
        // e.g. macOS `/tmp` -> `/private/tmp`: base given via the symlink,
        // target expressed through the same symlink must stay accepted.
        let real = tempfile::tempdir().unwrap();
        let holder = tempfile::tempdir().unwrap();
        let alias = holder.path().join("alias");
        std::os::unix::fs::symlink(real.path(), &alias).unwrap();
        resolve_contained(&alias, Path::new("rules.yaml")).expect("contained path must resolve");
    }
}
