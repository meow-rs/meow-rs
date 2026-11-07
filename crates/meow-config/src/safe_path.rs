//! Containment checks for config-supplied provider paths (issue #429).
//!
//! A `path:` on a rule- or proxy-provider is attacker-influenced whenever the
//! config document arrives over the REST API (`PUT /configs`), so every path
//! read or written on behalf of a provider must stay inside the provider
//! cache directory — mirroring mihomo's `C.Path.IsSafePath` guard.

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

/// mihomo's `SAFE_PATHS`: extra roots, separated like `PATH`, that provider
/// paths may live under besides the provider directory — the sanctioned way
/// to point providers at, e.g., a tmpfs (OpenWrt) without dropping the
/// guard. Compared lexically and, for symlinks, on resolved forms.
///
/// Environment is process-global and `SAFE_PATHS` is set before launch in
/// every supported deployment, so the parsed roots — **and** their
/// canonicalized forms, each of which otherwise costs filesystem syscalls
/// per path validated — are computed once and pinned behind a `OnceLock`.
fn safe_paths() -> &'static SafePaths {
    static SAFE_PATHS: std::sync::OnceLock<SafePaths> = std::sync::OnceLock::new();
    SAFE_PATHS.get_or_init(|| {
        SafePaths::from_lexical(
            std::env::var_os("SAFE_PATHS")
                .map(|v| split_safe_paths(&v))
                .unwrap_or_default(),
        )
    })
}

/// Parse the `SAFE_PATHS` list into normalized absolute roots: split like
/// `PATH`, then — matching mihomo's per-entry `strings.TrimSpace` — a
/// padded entry is honoured trimmed and an empty one dropped, as is any
/// non-absolute one (a relative root could never contain the absolute
/// target it is compared against).
fn split_safe_paths(v: &std::ffi::OsStr) -> Vec<PathBuf> {
    std::env::split_paths(v)
        .map(|p| match p.to_str() {
            Some(s) => PathBuf::from(s.trim()),
            None => p,
        })
        .filter(|p| !p.as_os_str().is_empty() && p.is_absolute())
        .filter_map(|p| normalize_absolute(&p).ok())
        .collect()
}

/// The two views of `SAFE_PATHS` one check needs: `lexical` roots for the
/// normalized-form comparison, and each root's canonicalized form for the
/// resolved-form comparison. The resolved-form stage runs second and sees
/// only targets the lexical stage already admitted: it *rejects* a
/// symlink — under `base` or under a listed root — pointing outside every
/// root, and it *admits* a symlink under `base` that resolves into a
/// listed root. A target *spelled* through the resolved side of a
/// symlinked root (`/private/tmp/…` for a `/tmp` entry) never reaches it:
/// the lexical stage rejects first, and canonical comparison cannot
/// rescue what that check already refused.
#[derive(Default)]
struct SafePaths {
    lexical: Vec<PathBuf>,
    canonical: Vec<PathBuf>,
}

impl SafePaths {
    fn from_lexical(lexical: Vec<PathBuf>) -> Self {
        let canonical = lexical
            .iter()
            .map(|root| canonicalize_existing_prefix(root))
            .collect();
        Self { lexical, canonical }
    }
}

/// The truthy half of Go's `strconv.ParseBool` accepted values.
fn go_parse_bool_truthy(value: &str) -> bool {
    matches!(value, "1" | "t" | "T" | "true" | "TRUE" | "True")
}

/// Resolve `requested` against `base` and require the result to stay inside
/// `base`.
///
/// Robust to `..` traversal (paths are lexically normalized before the prefix
/// check), absolute paths (allowed only when they already point inside
/// `base`), and symlink tricks (the deepest existing ancestor of both sides
/// is canonicalized and containment is re-checked on the resolved forms).
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
    resolve_contained_impl(base, requested, skip_safe_path_check(), safe_paths())
}

fn resolve_contained_impl(
    base: &Path,
    requested: &Path,
    skip_check: bool,
    safe: &SafePaths,
) -> Result<PathBuf, String> {
    let abs_base = normalize_absolute(base)?;
    let joined = if requested.is_absolute() {
        requested.to_path_buf()
    } else {
        abs_base.join(requested)
    };
    let abs_joined = normalize_absolute(&joined)?;
    let in_safe = |p: &Path, canon: bool| {
        let roots = if canon {
            &safe.canonical
        } else {
            &safe.lexical
        };
        roots.iter().any(|root| p.starts_with(root))
    };
    if !abs_joined.starts_with(&abs_base) && !in_safe(&abs_joined, false) {
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
    // A symlink already present under `base` could still redirect the I/O
    // outside of it; compare the symlink-resolved forms as well.
    let canon_base = canonicalize_existing_prefix(&abs_base);
    let canon_joined = canonicalize_existing_prefix(&abs_joined);
    if !canon_joined.starts_with(&canon_base) && !in_safe(&canon_joined, true) {
        if skip_check {
            warn_skip_active(requested, base, " via a symlink");
            return Ok(abs_joined);
        }
        return Err(format!(
            "path '{}' escapes the provider directory '{}' via a symlink",
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

/// Canonicalize the deepest existing ancestor of `path` (resolving symlinks)
/// and re-append the — already lexically normalized — non-existing remainder.
fn canonicalize_existing_prefix(path: &Path) -> PathBuf {
    let mut existing = path;
    let mut suffix: Vec<std::ffi::OsString> = Vec::new();
    loop {
        match existing.canonicalize() {
            Ok(canon) => {
                let mut out = canon;
                for c in suffix.iter().rev() {
                    out.push(c);
                }
                return out;
            }
            Err(_) => match existing.parent() {
                Some(parent) => {
                    if let Some(name) = existing.file_name() {
                        suffix.push(name.to_os_string());
                    }
                    existing = parent;
                }
                None => return path.to_path_buf(),
            },
        }
    }
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
    fn symlink_escape_is_rejected() {
        let outside = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("link")).unwrap();
        let err = resolve_contained(base.path(), Path::new("link/pwned")).unwrap_err();
        assert!(err.contains("symlink"), "unexpected: {err}");
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
            let err =
                resolve_contained_impl(dir.path(), Path::new(p), false, &SafePaths::default())
                    .expect_err("skip=false must keep the containment guarantee");
            assert!(err.contains("escapes"), "path {p}: unexpected: {err}");
        }
    }

    #[test]
    fn escape_hatch_on_allows_out_of_root_paths_with_warning() {
        let dir = tempfile::tempdir().unwrap();
        let got = resolve_contained_impl(
            dir.path(),
            Path::new("/etc/cron.d/pwned"),
            true,
            &SafePaths::default(),
        )
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
        let got = resolve_contained_impl(
            dir.path(),
            Path::new("sub/../../outside"),
            true,
            &SafePaths::default(),
        )
        .unwrap();
        assert!(!got.to_string_lossy().contains(".."));
    }

    /// mihomo `strings.TrimSpace` per `SplitList` entry: padded roots are
    /// honoured trimmed, empty and relative entries dropped, `..` folded.
    #[test]
    fn safe_paths_entries_are_trimmed_and_filtered() {
        let abs_a = tempfile::tempdir().unwrap();
        let abs_b = tempfile::tempdir().unwrap();
        let joined = std::env::join_paths([
            PathBuf::from(format!("  {}  ", abs_a.path().display())),
            PathBuf::from("relative/dir"),
            abs_b
                .path()
                .join("..")
                .join(abs_b.path().file_name().unwrap()),
        ])
        .unwrap();
        let got = split_safe_paths(&joined);
        assert_eq!(
            got,
            vec![abs_a.path().to_path_buf(), abs_b.path().to_path_buf()],
            "the padded entry must survive trimmed, `..` must fold, the \
             relative entry must drop"
        );
    }

    /// mihomo `SAFE_PATHS`: a symlink (or an absolute path) into a listed
    /// root is accepted; one elsewhere is still refused.
    #[cfg(unix)]
    #[test]
    fn safe_paths_admit_a_symlinked_root() {
        let tmpfs = tempfile::tempdir().unwrap();
        let elsewhere = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(tmpfs.path(), base.path().join("ram")).unwrap();
        std::os::unix::fs::symlink(elsewhere.path(), base.path().join("other")).unwrap();
        let safe = SafePaths::from_lexical(vec![tmpfs.path().to_path_buf()]);
        resolve_contained_impl(base.path(), Path::new("ram/rules.mrs"), false, &safe)
            .expect("symlink into a SAFE_PATHS root");
        resolve_contained_impl(base.path(), &tmpfs.path().join("x.yaml"), false, &safe)
            .expect("absolute path under a SAFE_PATHS root");
        resolve_contained_impl(base.path(), Path::new("other/pwned"), false, &safe)
            .expect_err("symlink outside every root");
    }

    #[cfg(unix)]
    #[test]
    fn escape_hatch_on_allows_symlink_escape() {
        let outside = tempfile::tempdir().unwrap();
        let base = tempfile::tempdir().unwrap();
        std::os::unix::fs::symlink(outside.path(), base.path().join("link")).unwrap();
        resolve_contained_impl(
            base.path(),
            Path::new("link/pwned"),
            true,
            &SafePaths::default(),
        )
        .expect("skip=true must allow the symlink escape");
        // …and skip=false still rejects the very same layout.
        resolve_contained_impl(
            base.path(),
            Path::new("link/pwned"),
            false,
            &SafePaths::default(),
        )
        .expect_err("skip=false must reject the symlink escape");
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
