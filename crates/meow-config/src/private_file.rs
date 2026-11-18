use std::fs::{self, File, OpenOptions};
use std::io::{self, Write as _};
use std::path::{Path, PathBuf};

const OWNER_READ_WRITE: u32 = 0o600;

pub(crate) fn save_config(path: &Path, yaml: &str) -> io::Result<()> {
    stage_config(path, yaml)?.publish()
}

pub(crate) async fn save_config_async(path: &Path, yaml: String) -> anyhow::Result<()> {
    let path = path.to_path_buf();
    let config =
        crate::spawn_blocking_with_current_dispatcher(move || stage_config(&path, &yaml)).await??;
    // A save cancelled during staging drops the pending files. The caller
    // only starts publication once staging has completed under its save lane.
    crate::spawn_blocking_with_current_dispatcher(move || config.publish()).await??;
    Ok(())
}

pub(crate) async fn write_cache(path: &Path, bytes: Vec<u8>) {
    let path = path.to_path_buf();
    let staged = crate::spawn_blocking_with_current_dispatcher(move || {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        stage_write(&path, OWNER_READ_WRITE, |file| file.write_all(&bytes))
    })
    .await;
    if let Ok(Ok(staged)) = staged {
        let _ = crate::spawn_blocking_with_current_dispatcher(move || staged.publish()).await;
    }
}

struct StagedConfig {
    config: StagedWrite,
    backup: Option<StagedWrite>,
}

impl StagedConfig {
    fn publish(self) -> io::Result<()> {
        if let Some(backup) = self.backup {
            let _ = backup.publish();
        }
        self.config.publish()
    }
}

fn stage_config(path: &Path, yaml: &str) -> io::Result<StagedConfig> {
    let config = stage_write(path, OWNER_READ_WRITE, |file| {
        file.write_all(yaml.as_bytes())
    })?;
    // Keep the backup best-effort and the live file in place until the
    // replacement is ready to publish.
    let backup = stage_backup(path);
    Ok(StagedConfig { config, backup })
}

fn stage_backup(path: &Path) -> Option<StagedWrite> {
    if !fs::symlink_metadata(path).ok()?.is_file() {
        return None;
    }
    let mut options = OpenOptions::new();
    options.read(true);
    // A config path changed during staging must not redirect the backup
    // to another file or cause us to block opening a FIFO.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut source = options.open(path).ok()?;
    let metadata = source.metadata().ok()?;
    if !metadata.is_file() {
        return None;
    }
    let mut backup_path = path.as_os_str().to_os_string();
    backup_path.push(".bak");
    stage_write(Path::new(&backup_path), private_mode(&metadata), |file| {
        io::copy(&mut source, file)?;
        Ok(())
    })
    .ok()
}

struct StagedWrite {
    scratch: PathBuf,
    target: PathBuf,
    published: bool,
}

impl StagedWrite {
    fn publish(mut self) -> io::Result<()> {
        fs::rename(&self.scratch, &self.target)?;
        self.published = true;
        Ok(())
    }
}

impl Drop for StagedWrite {
    fn drop(&mut self) {
        if !self.published {
            let _ = fs::remove_file(&self.scratch);
        }
    }
}

/// Creates the scratch file with private permissions before writing any
/// credentials. Exclusive creation keeps each writer on its own inode.
fn stage_write(
    path: &Path,
    mode: u32,
    write: impl FnOnce(&mut File) -> io::Result<()>,
) -> io::Result<StagedWrite> {
    meow_common::fs_util::sweep_scratch_siblings(path, meow_common::fs_util::SCRATCH_STALE_AGE);
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        let existing_mode = fs::metadata(path)
            .ok()
            .filter(fs::Metadata::is_file)
            .map_or(OWNER_READ_WRITE, |metadata| private_mode(&metadata));
        options.mode(mode & existing_mode);
    }
    #[cfg(not(unix))]
    let _ = mode;

    let (scratch, mut file) = loop {
        let scratch = crate::unique_scratch_path(path);
        match options.open(&scratch) {
            Ok(file) => break (scratch, file),
            // A recent scratch file can survive a restart with the same
            // PID, notably when the process runs as PID 1 in a container.
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => continue,
            Err(err) => return Err(err),
        }
    };
    let staged = StagedWrite {
        scratch,
        target: path.to_path_buf(),
        published: false,
    };
    let result = write(&mut file);
    drop(file);
    result?;
    Ok(staged)
}

fn private_mode(metadata: &fs::Metadata) -> u32 {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        metadata.permissions().mode() & OWNER_READ_WRITE
    }
    #[cfg(not(unix))]
    {
        let _ = metadata;
        OWNER_READ_WRITE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discarded_save_leaves_live_files_and_removes_scratch() {
        let dir = tempfile::tempdir().unwrap();
        let config = dir.path().join("config.yaml");
        let backup = dir.path().join("config.yaml.bak");
        fs::write(&config, "mode: rule").unwrap();
        fs::write(&backup, "mode: global").unwrap();

        let pending = stage_config(&config, "mode: direct").unwrap();
        assert!(pending.backup.is_some());
        assert_eq!(fs::read_to_string(&config).unwrap(), "mode: rule");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "mode: global");
        drop(pending);

        assert_eq!(fs::read_to_string(&config).unwrap(), "mode: rule");
        assert_eq!(fs::read_to_string(&backup).unwrap(), "mode: global");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 2);
    }
}
