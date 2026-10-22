//! The controller file: how `meow-cli` finds a running meow without being
//! told where its API is.
//!
//! Once its `external-controller` is bound, meow writes `<pid>.json` into
//! [`dir`]: the address a client on this host dials, the API secret and the
//! config path. Only the user meow runs as can read it: the file is 0600 in
//! a 0700 directory on unix, and lives under the per-user `%LOCALAPPDATA%`
//! on Windows. A meow running as root writes to `/var/run/meow`, for root.
//!
//! meow holds a shared lock on its file for as long as it runs and removes
//! the file on the way out. A file nobody holds a lock on belongs to a meow
//! that died; whoever lists the directory next removes it. The lock, not the
//! pid, is the liveness test, so a reused pid cannot pass for a live meow.

use std::fs::{self, File, OpenOptions, TryLockError};
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

/// Environment variable that overrides [`dir`].
pub const DIR_ENV: &str = "MEOW_RUNTIME_DIR";

/// One running meow, as its controller file describes it.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub pid: u32,
    /// The address a client on this host dials: an unspecified bind
    /// address (`0.0.0.0`, `::`) is written as the loopback.
    pub controller: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,
    /// The config file meow loaded; absent for `--config-string`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub config: Option<PathBuf>,
}

impl std::fmt::Debug for Entry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Entry")
            .field("pid", &self.pid)
            .field("controller", &self.controller)
            .field("secret", &self.secret.as_ref().map(|_| "<redacted>"))
            .field("config", &self.config)
            .finish()
    }
}

/// Keeps a controller file published; dropping it removes the file.
pub struct Published {
    path: PathBuf,
    // Held for its shared lock, which marks the file live.
    _file: File,
}

impl Drop for Published {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

/// The directory controller files live in: [`DIR_ENV`] when set, else
/// `/var/run/meow/controllers` for root, `~/Library/Caches/meow/controllers`
/// on macOS, `~/.cache/meow/controllers` on other unix systems and
/// `%LOCALAPPDATA%\meow\controllers` on Windows. `None` on mobile systems
/// and without a home directory.
pub fn dir() -> Option<PathBuf> {
    match std::env::var_os(DIR_ENV) {
        Some(dir) if !dir.is_empty() => Some(PathBuf::from(dir)),
        _ => platform_dir(),
    }
}

#[cfg(all(
    unix,
    not(any(target_os = "android", target_os = "ios", target_os = "tvos"))
))]
fn platform_dir() -> Option<PathBuf> {
    if euid() == 0 {
        return Some(PathBuf::from("/var/run/meow/controllers"));
    }
    let home = PathBuf::from(std::env::var_os("HOME").filter(|home| !home.is_empty())?);
    let cache = if cfg!(target_os = "macos") {
        home.join("Library/Caches")
    } else {
        home.join(".cache")
    };
    Some(cache.join("meow/controllers"))
}

#[cfg(windows)]
fn platform_dir() -> Option<PathBuf> {
    let local = std::env::var_os("LOCALAPPDATA").filter(|dir| !dir.is_empty())?;
    Some(PathBuf::from(local).join("meow").join("controllers"))
}

#[cfg(not(any(
    windows,
    all(
        unix,
        not(any(target_os = "android", target_os = "ios", target_os = "tvos"))
    )
)))]
fn platform_dir() -> Option<PathBuf> {
    None
}

/// Publishes this process's controller in [`dir`]; `Ok(None)` where there
/// is no such directory.
pub fn publish(
    controller: SocketAddr,
    secret: Option<&str>,
    config: Option<&Path>,
) -> io::Result<Option<Published>> {
    match dir() {
        Some(dir) => publish_in(&dir, controller, secret, config).map(Some),
        None => Ok(None),
    }
}

/// Publishes this process's controller in `dir`, which is created if need
/// be. Errors name the directory.
pub fn publish_in(
    dir: &Path,
    controller: SocketAddr,
    secret: Option<&str>,
    config: Option<&Path>,
) -> io::Result<Published> {
    let pid = std::process::id();
    let entry = Entry {
        pid,
        controller: local_address(controller),
        secret: secret
            .filter(|secret| !secret.is_empty())
            .map(str::to_owned),
        config: config.map(|path| std::path::absolute(path).unwrap_or_else(|_| path.to_owned())),
    };
    let in_dir =
        |error: io::Error| io::Error::new(error.kind(), format!("{}: {error}", dir.display()));
    create_private_dir(dir).map_err(in_dir)?;
    // Clear out what meows that died left behind.
    running_in(dir);

    // Written under another name and renamed into place already locked, so
    // no one sees `<pid>.json` unlocked or half written. Windows denies
    // writes under a shared lock, the writer's own included: write first.
    let scratch = dir.join(format!("{pid}.tmp"));
    let path = dir.join(format!("{pid}.json"));
    let _ = fs::remove_file(&scratch);
    let written = (|| {
        let mut file = create_private_file(&scratch)?;
        file.write_all(&serde_json::to_vec(&entry)?)?;
        file.lock_shared()?;
        fs::rename(&scratch, &path)?;
        Ok(file)
    })();
    match written {
        Ok(file) => Ok(Published { path, _file: file }),
        Err(error) => {
            let _ = fs::remove_file(&scratch);
            Err(in_dir(error))
        }
    }
}

/// The meows running as this user, by pid; removes the files of those
/// that died.
pub fn running() -> Vec<Entry> {
    dir().map(|dir| running_in(&dir)).unwrap_or_default()
}

/// [`running`], for the files in `dir`.
pub fn running_in(dir: &Path) -> Vec<Entry> {
    let Ok(listing) = fs::read_dir(dir) else {
        return Vec::new();
    };
    let mut entries = Vec::new();
    for item in listing.flatten() {
        let path = item.path();
        // Regular files only: opening a FIFO would block, and a symlink
        // could stand in for a file this user does not own.
        if path.extension().is_none_or(|extension| extension != "json")
            || !item.file_type().is_ok_and(|kind| kind.is_file())
        {
            continue;
        }
        let Ok(mut file) = File::open(&path) else {
            continue;
        };
        if !owned_by_this_user(&file) {
            continue;
        }
        match file.try_lock() {
            // Nobody holds it: its meow is gone.
            Ok(()) => {
                let _ = fs::remove_file(&path);
            }
            Err(TryLockError::WouldBlock) => {
                let mut text = String::new();
                if file.read_to_string(&mut text).is_ok() {
                    if let Ok(entry) = serde_json::from_str(&text) {
                        entries.push(entry);
                    }
                }
            }
            // No locks on this filesystem, so no telling: meow publishes
            // only under a lock, so this file is not one of its own.
            Err(TryLockError::Error(_)) => {}
        }
    }
    entries.sort_by_key(|entry: &Entry| entry.pid);
    entries
}

/// The address a client on this host dials for a listener bound to `addr`.
fn local_address(mut addr: SocketAddr) -> SocketAddr {
    if addr.ip().is_unspecified() {
        addr.set_ip(match addr.ip() {
            IpAddr::V4(_) => IpAddr::V4(Ipv4Addr::LOCALHOST),
            IpAddr::V6(_) => IpAddr::V6(Ipv6Addr::LOCALHOST),
        });
    }
    addr
}

#[cfg(unix)]
fn euid() -> libc::uid_t {
    // SAFETY: geteuid has no preconditions and cannot fail.
    unsafe { libc::geteuid() }
}

#[cfg(unix)]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(dir)
}

#[cfg(not(unix))]
fn create_private_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)
}

#[cfg(unix)]
fn create_private_file(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
}

#[cfg(not(unix))]
fn create_private_file(path: &Path) -> io::Result<File> {
    OpenOptions::new().write(true).create_new(true).open(path)
}

/// Only a file this user owns can point meow-cli at a controller and hand
/// it a secret to send there.
#[cfg(unix)]
fn owned_by_this_user(file: &File) -> bool {
    use std::os::unix::fs::MetadataExt as _;
    file.metadata()
        .is_ok_and(|metadata| metadata.uid() == euid())
}

#[cfg(not(unix))]
fn owned_by_this_user(_file: &File) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(text: &str) -> SocketAddr {
        text.parse().unwrap()
    }

    #[test]
    fn a_published_controller_reads_back_until_dropped() {
        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("controllers");
        let published = publish_in(
            &runtime,
            addr("0.0.0.0:9090"),
            Some("s3cret"),
            Some(Path::new("config.yaml")),
        )
        .unwrap();

        let running = running_in(&runtime);
        assert_eq!(running.len(), 1, "{running:?}");
        let entry = &running[0];
        assert_eq!(entry.pid, std::process::id());
        assert_eq!(entry.controller, addr("127.0.0.1:9090"));
        assert_eq!(entry.secret.as_deref(), Some("s3cret"));
        let config = entry.config.as_deref().unwrap();
        assert!(
            config.is_absolute() && config.ends_with("config.yaml"),
            "{config:?}"
        );

        // Listing a live file leaves it in place.
        assert_eq!(running_in(&runtime).len(), 1);
        drop(published);
        assert!(running_in(&runtime).is_empty());
        assert_eq!(fs::read_dir(&runtime).unwrap().count(), 0);
    }

    #[test]
    fn an_empty_secret_is_left_out() {
        let dir = tempfile::tempdir().unwrap();
        let _published = publish_in(dir.path(), addr("[::]:9090"), Some(""), None).unwrap();
        let text =
            fs::read_to_string(dir.path().join(format!("{}.json", std::process::id()))).unwrap();
        assert!(
            !text.contains("secret") && !text.contains("config"),
            "{text}"
        );
        let running = running_in(dir.path());
        assert_eq!(running[0].controller, addr("[::1]:9090"));
    }

    #[test]
    fn a_dead_meows_file_is_swept() {
        let dir = tempfile::tempdir().unwrap();
        // What a meow killed with SIGKILL leaves: a file nobody locks.
        let stale = dir.path().join("4242.json");
        fs::write(&stale, r#"{"pid":4242,"controller":"127.0.0.1:9091"}"#).unwrap();
        let other = dir.path().join("gateway.nft");
        fs::write(&other, "table inet meow {}").unwrap();

        assert!(running_in(dir.path()).is_empty());
        assert!(!stale.exists());
        assert!(other.exists(), "only controller files are swept");
    }

    #[test]
    fn the_secret_stays_out_of_debug_output() {
        let entry = Entry {
            pid: 1,
            controller: addr("127.0.0.1:9090"),
            secret: Some("s3cret".into()),
            config: None,
        };
        let text = format!("{entry:?}");
        assert!(
            !text.contains("s3cret") && text.contains("<redacted>"),
            "{text}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn only_this_user_can_read_it() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = tempfile::tempdir().unwrap();
        let runtime = dir.path().join("a/controllers");
        let _published =
            publish_in(&runtime, addr("127.0.0.1:9090"), Some("s3cret"), None).unwrap();
        let mode = |path: &Path| fs::metadata(path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&runtime), 0o700);
        assert_eq!(
            mode(&runtime.join(format!("{}.json", std::process::id()))),
            0o600
        );
    }
}
