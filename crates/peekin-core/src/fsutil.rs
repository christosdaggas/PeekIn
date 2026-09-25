//! Crash-safe file replacement for config and model files.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

/// Replace `path` atomically (temp file, fsync, rename). `mode: None` keeps
/// the existing mode (0600 if new).
pub fn atomic_write(path: &Path, contents: &[u8], mode: Option<u32>) -> io::Result<()> {
    let mode = match mode {
        Some(m) => m,
        None => fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o7777)
            .unwrap_or(0o600),
    };
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| {
        let mut f = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&tmp)?;
        f.write_all(contents)?;
        // create_new applies the umask; set the exact mode explicitly.
        f.set_permissions(fs::Permissions::from_mode(mode))?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Like [`atomic_write`], with ownership set before the rename.
pub fn atomic_write_owned(
    path: &Path,
    contents: &[u8],
    mode: u32,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<()> {
    if let Ok(metadata) = fs::symlink_metadata(path) {
        if !metadata.file_type().is_file() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "destination is not a regular file",
            ));
        }
    }
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no file name"))?;
    let tmp = dir.join(format!(
        ".{}.tmp{}",
        name.to_string_lossy(),
        std::process::id()
    ));

    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .mode(0o600)
            .open(&tmp)?;
        if unsafe { libc::fchown(file.as_raw_fd(), uid, gid) } != 0 {
            return Err(io::Error::last_os_error());
        }
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        file.write_all(contents)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        File::open(dir)?.sync_all()
    })();
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

pub fn create_dir_all_mode(path: &Path, mode: u32) -> io::Result<()> {
    fs::DirBuilder::new()
        .recursive(true)
        .mode(mode)
        .create(path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmpdir(name: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("peekin-fsutil-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&p);
        fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn new_file_gets_requested_mode() {
        let d = tmpdir("mode");
        let f = d.join("a.dat");
        atomic_write(&f, b"x", Some(0o600)).unwrap();
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&f).unwrap(), b"x");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn replace_keeps_existing_mode_and_leaves_no_temp_file() {
        let d = tmpdir("keep");
        let f = d.join("config.ini");
        fs::write(&f, "old").unwrap();
        fs::set_permissions(&f, fs::Permissions::from_mode(0o644)).unwrap();
        atomic_write(&f, b"new", None).unwrap();
        assert_eq!(fs::read_to_string(&f).unwrap(), "new");
        assert_eq!(
            fs::metadata(&f).unwrap().permissions().mode() & 0o777,
            0o644
        );
        assert_eq!(fs::read_dir(&d).unwrap().count(), 1);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn created_dirs_get_mode() {
        let d = tmpdir("dirs");
        let nested = d.join("a/b");
        create_dir_all_mode(&nested, 0o700).unwrap();
        assert_eq!(
            fs::metadata(&nested).unwrap().permissions().mode() & 0o777,
            0o700
        );
        let _ = fs::remove_dir_all(&d);
    }
}
