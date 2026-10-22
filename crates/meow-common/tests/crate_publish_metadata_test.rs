//! Gates crate metadata and crate-level rustdoc for crates.io / docs.rs.
//!
//! Drives `cargo metadata --format-version 1` on the real workspace (not a
//! re-typed copy of the TOMLs) and reads each publishable crate's library
//! root from the paths metadata reports.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

const EXPECTED_REPOSITORY: &str = "https://github.com/meow-rs/meow-rs";
const EXPECTED_HOMEPAGE: &str = "https://meow-rs.github.io/meow-rs/";

const PUBLISHABLE: &[&str] = &[
    "meow-common",
    "meow-trie",
    "meow-anytls",
    "meow-lwip",
    "meow-transport",
    "meow-rules",
    "meow-dns",
    "meow-proxy",
    "meow-config",
    "meow-tunnel",
    "meow-listener",
    "meow-api",
    "meow-app",
];

const UNPUBLISHED: &[&str] = &["meow-bench", "meow-cli"];

fn workspace_root() -> PathBuf {
    let mut dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    loop {
        let toml = dir.join("Cargo.toml");
        if let Ok(text) = fs::read_to_string(&toml) {
            if text.contains("[workspace]") && text.contains("members") {
                return dir;
            }
        }
        assert!(
            dir.pop(),
            "workspace root not found walking up from {}",
            env!("CARGO_MANIFEST_DIR")
        );
    }
}

fn cargo_metadata() -> serde_json::Value {
    let output = Command::new("cargo")
        .args(["metadata", "--format-version", "1", "--no-deps"])
        .current_dir(workspace_root())
        .output()
        .expect("failed to spawn cargo metadata");
    assert!(
        output.status.success(),
        "cargo metadata failed:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("cargo metadata JSON")
}

fn workspace_packages(meta: &serde_json::Value) -> Vec<&serde_json::Value> {
    let members: HashSet<&str> = meta["workspace_members"]
        .as_array()
        .expect("workspace_members")
        .iter()
        .map(|id| id.as_str().expect("workspace member id"))
        .collect();
    meta["packages"]
        .as_array()
        .expect("packages")
        .iter()
        .filter(|pkg| members.contains(pkg["id"].as_str().expect("package id")))
        .collect()
}

fn can_publish(pkg: &serde_json::Value) -> bool {
    match pkg.get("publish") {
        Some(serde_json::Value::Array(regs)) => !regs.is_empty(),
        _ => true,
    }
}

fn package_version(pkg: &serde_json::Value) -> &str {
    pkg["version"].as_str().expect("package version")
}

fn lib_src_path(pkg: &serde_json::Value) -> &Path {
    let name = pkg["name"].as_str().unwrap();
    let target = pkg["targets"]
        .as_array()
        .expect("targets")
        .iter()
        .find(|t| {
            t["kind"]
                .as_array()
                .into_iter()
                .flatten()
                .any(|k| k.as_str() == Some("lib"))
        })
        .unwrap_or_else(|| panic!("{name} has no lib target"));
    Path::new(target["src_path"].as_str().expect("src_path"))
}

/// Crate-level rustdoc that rustc will attach to the crate root: a leading
/// `//!` block, or a leading `#![doc = include_str!("…")]` whose included
/// file is read from disk.
fn opening_crate_docs(src_path: &Path) -> String {
    let src =
        fs::read_to_string(src_path).unwrap_or_else(|e| panic!("read {}: {e}", src_path.display()));
    let mut collected = String::new();
    let mut saw_doc = false;
    for line in src.lines() {
        let trimmed = line.trim_start();
        if trimmed.is_empty() {
            if saw_doc {
                collected.push('\n');
            }
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("//!") {
            saw_doc = true;
            collected.push_str(rest.strip_prefix(' ').unwrap_or(rest));
            collected.push('\n');
            continue;
        }
        if trimmed.starts_with("#![doc") {
            if let Some(rel) = include_str_path(trimmed) {
                let included = src_path.parent().expect("lib src parent").join(rel);
                return fs::read_to_string(&included).unwrap_or_else(|e| {
                    panic!(
                        "read included rustdoc {} from {}: {e}",
                        included.display(),
                        src_path.display()
                    )
                });
            }
            saw_doc = true;
            collected.push_str(trimmed);
            collected.push('\n');
            continue;
        }
        if saw_doc {
            break;
        }
        panic!(
            "{} must begin with crate-level rustdoc (`//!` or `#![doc = …]`), found: {trimmed}",
            src_path.display()
        );
    }
    assert!(
        saw_doc && !collected.trim().is_empty(),
        "{} has empty crate-level rustdoc",
        src_path.display()
    );
    collected
}

fn include_str_path(attr: &str) -> Option<&str> {
    let rest = attr.strip_prefix("#![doc")?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=')?.trim_start();
    let rest = rest.strip_prefix("include_str!")?.trim_start();
    let rest = rest.strip_prefix('(')?.trim_start();
    let quote = rest.chars().next()?;
    if quote != '"' && quote != '\'' {
        return None;
    }
    let inner = rest[1..].split(quote).next()?;
    Some(inner)
}

#[test]
fn publishable_crates_advertise_org_urls() {
    let meta = cargo_metadata();
    let packages = workspace_packages(&meta);
    let mut seen_publishable = HashSet::new();
    let mut seen_unpublished = HashSet::new();

    for pkg in &packages {
        let name = pkg["name"].as_str().expect("package name");
        if UNPUBLISHED.contains(&name) {
            assert!(
                !can_publish(pkg),
                "{name} must stay unpublished (`publish = false`)"
            );
            seen_unpublished.insert(name);
            continue;
        }
        assert!(
            PUBLISHABLE.contains(&name),
            "{name} is a workspace member that can publish but is not in the 13-crate crates.io set"
        );
        assert!(
            can_publish(pkg),
            "{name} is a publishable crate but cargo metadata reports publish disabled"
        );
        assert_eq!(
            pkg["repository"].as_str(),
            Some(EXPECTED_REPOSITORY),
            "{name} repository"
        );
        assert_eq!(
            pkg["homepage"].as_str(),
            Some(EXPECTED_HOMEPAGE),
            "{name} homepage"
        );
        seen_publishable.insert(name);
    }

    for name in PUBLISHABLE {
        assert!(
            seen_publishable.contains(name),
            "{name} missing from cargo metadata workspace packages"
        );
    }
    for name in UNPUBLISHED {
        assert!(
            seen_unpublished.contains(name),
            "{name} missing from cargo metadata workspace packages"
        );
    }
    assert_eq!(seen_publishable.len(), PUBLISHABLE.len());
}

/// The workspace releases in lockstep: every member is at one version and
/// every dependency on a member pins exactly that version. This is the
/// invariant `scripts/release/prepare.sh` maintains on a bump; a pin left
/// at the previous version would make `cargo publish` resolve the previous
/// release from crates.io instead of the crate being published alongside it.
#[test]
fn workspace_crates_release_in_lockstep() {
    let meta = cargo_metadata();
    let packages = workspace_packages(&meta);
    let members: HashSet<&str> = packages
        .iter()
        .map(|pkg| pkg["name"].as_str().expect("package name"))
        .collect();
    let workspace_version = packages
        .iter()
        .find(|pkg| pkg["name"] == "meow-common")
        .map(|pkg| package_version(pkg))
        .expect("meow-common in workspace");
    let pin = format!("^{workspace_version}");

    for pkg in &packages {
        let name = pkg["name"].as_str().expect("package name");
        assert_eq!(
            package_version(pkg),
            workspace_version,
            "{name} is not at the workspace version"
        );
        for dep in pkg["dependencies"].as_array().expect("dependencies") {
            let dep_name = dep["name"].as_str().expect("dependency name");
            if !members.contains(dep_name) {
                continue;
            }
            let req = dep["req"].as_str().expect("dependency req");
            if req == "*" && !can_publish(pkg) {
                continue;
            }
            assert_eq!(
                req, pin,
                "{name} depends on {dep_name} with `{req}`; workspace crates must pin `version = \"{workspace_version}\"`"
            );
        }
    }
}

#[test]
fn publishable_library_roots_have_crate_level_rustdoc() {
    let meta = cargo_metadata();
    let packages = workspace_packages(&meta);
    let mut checked = HashSet::new();

    for pkg in &packages {
        let name = pkg["name"].as_str().expect("package name");
        if !PUBLISHABLE.contains(&name) {
            continue;
        }
        let src_path = lib_src_path(pkg);
        let docs = opening_crate_docs(src_path);
        assert!(
            !docs.trim().is_empty(),
            "{name} crate-level rustdoc at {} is empty",
            src_path.display()
        );
        eprintln!(
            "{name}: crate-level rustdoc from {} ({} bytes)",
            src_path.display(),
            docs.len()
        );
        checked.insert(name);
    }

    for name in PUBLISHABLE {
        assert!(
            checked.contains(name),
            "{name} missing from cargo metadata workspace packages"
        );
    }
}
