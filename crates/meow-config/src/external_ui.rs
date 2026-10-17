//! Optional auto-download for a third-party web dashboard (issue #223).
//!
//! Compiled only with the `external-ui-download` feature. Fetches the zip named
//! by `external-ui-url` and extracts it into the `external-ui` directory, so the
//! API server can then serve it at `/ui`. Kept behind a feature because the
//! `zip` dependency grows the binary against the ADR-0007 size caps.

use anyhow::Context;
use std::io::Cursor;
use std::path::{Path, PathBuf};
use tracing::info;

/// Download the archive at `url` and extract it into `dir`.
///
/// GitHub branch/release zips wrap every entry in a single `<repo>-<ref>/`
/// directory; that common top-level prefix is stripped so the dashboard's
/// `index.html` lands directly in `dir`. Returns an error for the caller to log
/// — a failed download is non-fatal (the server falls back to the built-in UI).
pub async fn download_external_ui(url: &str, dir: &Path) -> anyhow::Result<()> {
    info!("Downloading external UI from {url} into {}", dir.display());
    let bytes = crate::internal_http::fetch_direct(url)
        .await
        .with_context(|| format!("request to {url} failed"))?;

    let dir_owned = dir.to_path_buf();
    // Zip extraction is synchronous and CPU/IO bound; keep it off the runtime.
    tokio::task::spawn_blocking(move || extract_zip(&bytes, &dir_owned))
        .await
        .context("extraction task panicked")??;
    info!("external UI extracted to {}", dir.display());
    Ok(())
}

fn extract_zip(bytes: &[u8], dir: &Path) -> anyhow::Result<()> {
    let mut archive =
        zip::ZipArchive::new(Cursor::new(bytes)).context("not a valid zip archive")?;
    let strip = common_top_level(&archive);

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // `enclosed_name` rejects absolute paths and `..` traversal — skip any
        // entry that does not resolve to a safe relative path (zip-slip guard).
        let Some(name) = entry.enclosed_name() else {
            continue;
        };
        let rel = match &strip {
            Some(prefix) => match name.strip_prefix(prefix) {
                Ok(r) if !r.as_os_str().is_empty() => r.to_path_buf(),
                _ => continue,
            },
            None => name,
        };
        let out = dir.join(rel);
        if entry.is_dir() {
            std::fs::create_dir_all(&out)?;
        } else {
            if let Some(parent) = out.parent() {
                std::fs::create_dir_all(parent)?;
            }
            let mut f = std::fs::File::create(&out)
                .with_context(|| format!("creating {}", out.display()))?;
            std::io::copy(&mut entry, &mut f)?;
        }
    }
    Ok(())
}

/// If every entry sits under one shared top-level directory, return it so it can
/// be stripped; otherwise `None`.
fn common_top_level(archive: &zip::ZipArchive<Cursor<&[u8]>>) -> Option<PathBuf> {
    // A name that does not decode is skipped: `extract_zip` never writes that
    // entry either (its `enclosed_name` is `None`).
    let mut names = archive.file_names().filter_map(Result::ok);
    let first = names.next()?;
    let top = first.split('/').next().filter(|s| !s.is_empty())?;
    let prefix = format!("{top}/");
    if archive
        .file_names()
        .filter_map(Result::ok)
        .all(|n| n == top || n.starts_with(&prefix))
    {
        Some(PathBuf::from(top))
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use zip::write::{SimpleFileOptions, ZipWriter};

    /// Build an in-memory zip from `(path, contents)` entries (Stored, no codec
    /// feature needed).
    fn make_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
        let mut buf = Vec::new();
        {
            let mut w = ZipWriter::new(Cursor::new(&mut buf));
            let opts =
                SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
            for (path, contents) in entries {
                w.start_file(*path, opts).unwrap();
                w.write_all(contents).unwrap();
            }
            w.finish().unwrap();
        }
        buf
    }

    #[test]
    fn strips_common_github_top_level_dir() {
        // GitHub-style: everything under `metacubexd-gh-pages/`.
        let zip = make_zip(&[
            ("metacubexd-gh-pages/index.html", b"<html>dash</html>"),
            ("metacubexd-gh-pages/assets/app.js", b"console.log(1)"),
        ]);
        let dir = tempfile::tempdir().unwrap();
        extract_zip(&zip, dir.path()).unwrap();

        // The wrapping directory is stripped: index.html lands at the root.
        assert_eq!(
            std::fs::read_to_string(dir.path().join("index.html")).unwrap(),
            "<html>dash</html>"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("assets/app.js")).unwrap(),
            "console.log(1)"
        );
        assert!(!dir.path().join("metacubexd-gh-pages").exists());
    }

    #[test]
    fn keeps_layout_when_no_common_prefix() {
        let zip = make_zip(&[("index.html", b"root"), ("vendor/lib.js", b"v")]);
        let dir = tempfile::tempdir().unwrap();
        extract_zip(&zip, dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("index.html")).unwrap(),
            "root"
        );
        assert_eq!(
            std::fs::read_to_string(dir.path().join("vendor/lib.js")).unwrap(),
            "v"
        );
    }

    #[test]
    fn rejects_zip_slip_traversal() {
        // `enclosed_name()` returns None for `..` escapes, so the entry is
        // skipped and nothing is written outside `dir`.
        let zip = make_zip(&[("../escape.txt", b"pwned"), ("safe.txt", b"ok")]);
        let dir = tempfile::tempdir().unwrap();
        extract_zip(&zip, dir.path()).unwrap();
        assert_eq!(
            std::fs::read_to_string(dir.path().join("safe.txt")).unwrap(),
            "ok"
        );
        assert!(!dir.path().parent().unwrap().join("escape.txt").exists());
    }
}
