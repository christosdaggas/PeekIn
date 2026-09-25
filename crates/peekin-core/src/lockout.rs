//! Pause face login after repeated failed face attempts.
//!
//! A root-only file per user under [`STATE_DIR`] holds `"<failures> <last time>"`.
//! I/O errors are returned for logging and must never block the password.

use crate::paths::validate_username;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const STATE_DIR: &str = "/var/lib/peekin/failures";
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Record {
    pub failures: u32,
    pub last: u64,
}

impl Record {
    fn parse(raw: &str) -> Record {
        let mut parts = raw.split_whitespace();
        match (
            parts.next().and_then(|v| v.parse().ok()),
            parts.next().and_then(|v| v.parse().ok()),
            parts.next(),
        ) {
            (Some(failures), Some(last), None) => Record { failures, last },
            // A damaged file starts over rather than locking anyone out.
            _ => Record::default(),
        }
    }

    pub fn current(self, now: u64) -> Record {
        if now.saturating_sub(self.last) >= LOCKOUT.as_secs() {
            Record::default()
        } else {
            self
        }
    }

    pub fn locked_until(self, now: u64, max_failures: u32) -> Option<u64> {
        let current = self.current(now);
        (max_failures > 0 && current.failures >= max_failures)
            .then(|| current.last + LOCKOUT.as_secs())
    }
}

pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

fn state_file(dir: &Path, user: &str) -> io::Result<PathBuf> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(dir.join(user))
}

fn ensure_dir(dir: &Path) -> io::Result<()> {
    match fs::symlink_metadata(dir) {
        Ok(meta) if meta.is_dir() && meta.uid() == unsafe { libc::geteuid() } => {
            if meta.mode() & 0o022 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    format!("{} is group/world-writable", dir.display()),
                ));
            }
            Ok(())
        }
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{} is not a directory owned by us", dir.display()),
        )),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            fs::DirBuilder::new().mode(0o700).create(dir)
        }
        Err(e) => Err(e),
    }
}

fn open_locked(dir: &Path, user: &str, create: bool) -> io::Result<Option<fs::File>> {
    let path = state_file(dir, user)?;
    if create {
        ensure_dir(dir)?;
    }
    let file = match OpenOptions::new()
        .read(true)
        .write(true)
        .create(create)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if !create && e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e),
    };
    if !file.metadata()?.is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a regular file", path.display()),
        ));
    }
    // SAFETY: flock on a descriptor we own; released when the file is dropped.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(Some(file))
}

fn read_record(file: &mut fs::File) -> io::Result<Record> {
    let mut raw = String::new();
    file.take(64).read_to_string(&mut raw)?;
    Ok(Record::parse(&raw))
}

pub fn load(dir: &Path, user: &str) -> io::Result<Record> {
    match open_locked(dir, user, false)? {
        Some(mut file) => read_record(&mut file),
        None => Ok(Record::default()),
    }
}

pub fn record_failure(dir: &Path, user: &str, now: u64) -> io::Result<Record> {
    let mut file = open_locked(dir, user, true)?.expect("created");
    let previous = read_record(&mut file)?.current(now);
    let record = Record {
        failures: previous.failures.saturating_add(1),
        last: now,
    };
    file.rewind()?;
    file.set_len(0)?;
    writeln!(file, "{} {}", record.failures, record.last)?;
    Ok(record)
}

pub fn reset(dir: &Path, user: &str) -> io::Result<()> {
    match fs::remove_file(state_file(dir, user)?) {
        Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("peekin-lockout-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn locks_after_max_failures_and_expires() {
        let d = dir("expire");
        let t = 1_000_000;
        for i in 1..=5 {
            let r = record_failure(&d, "alice", t + i).unwrap();
            assert_eq!(r.failures, i as u32);
        }
        let r = load(&d, "alice").unwrap();
        assert_eq!(r.locked_until(t + 5, 5), Some(t + 5 + LOCKOUT.as_secs()));
        assert_eq!(r.locked_until(t + 5, 6), None, "below the limit");
        assert_eq!(r.locked_until(t + 5, 0), None, "0 disables the limit");
        assert_eq!(
            r.locked_until(t + 5 + LOCKOUT.as_secs(), 5),
            None,
            "expired"
        );
        // An old streak does not count towards a new one.
        let fresh = record_failure(&d, "alice", t + 5 + LOCKOUT.as_secs() + 1).unwrap();
        assert_eq!(fresh.failures, 1);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn success_resets_and_state_is_private() {
        let d = dir("reset");
        record_failure(&d, "alice", 10).unwrap();
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(d.join("alice")).unwrap().mode() & 0o777, 0o600);
        reset(&d, "alice").unwrap();
        assert_eq!(load(&d, "alice").unwrap(), Record::default());
        reset(&d, "alice").unwrap();
        assert_eq!(load(&d.join("missing"), "bob").unwrap(), Record::default());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn rejects_unsafe_names_links_and_damaged_files() {
        let d = dir("unsafe");
        assert!(record_failure(&d, "../etc", 1).is_err());
        fs::create_dir_all(&d).unwrap();
        std::os::unix::fs::symlink("/etc/hostname", d.join("mallory")).unwrap();
        assert!(record_failure(&d, "mallory", 1).is_err());
        assert!(load(&d, "mallory").is_err());
        fs::write(d.join("carol"), "garbage here too\n").unwrap();
        assert_eq!(load(&d, "carol").unwrap(), Record::default());
        let _ = fs::remove_dir_all(d);
    }
}
