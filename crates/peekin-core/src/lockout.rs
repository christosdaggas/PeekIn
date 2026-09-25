//! Pause face login after repeated failed face attempts.
//!
//! A root-only file per user under [`STATE_DIR`] holds `"<failures> <last time>"`;
//! it is empty from its creation until the first failure is written.
//! I/O errors and damaged content are returned as errors: they stop face login
//! (fail closed) but must never block the password.

use crate::paths::validate_username;
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub const STATE_DIR: &str = "/var/lib/peekin/failures";
pub const LOCKOUT: Duration = Duration::from_secs(15 * 60);
/// Twice the longest record (32 bytes); longer content was not written here.
const MAX_RECORD_LEN: u64 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Record {
    pub failures: u32,
    pub last: u64,
}

impl Record {
    /// `None` for anything but `"<failures> <last time>"`.
    fn parse(raw: &str) -> Option<Record> {
        let mut parts = raw.split_whitespace();
        match (
            parts.next().and_then(|v| v.parse().ok()),
            parts.next().and_then(|v| v.parse().ok()),
            parts.next(),
        ) {
            (Some(failures), Some(last), None) => Some(Record { failures, last }),
            _ => None,
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

/// `None` when the file holds no valid record; empty means no failures yet.
fn read_record(file: &mut fs::File) -> io::Result<Option<Record>> {
    let mut raw = Vec::new();
    // One byte past the limit, so junk after a valid start is not cut off unseen.
    file.take(MAX_RECORD_LEN + 1).read_to_end(&mut raw)?;
    if raw.is_empty() {
        return Ok(Some(Record::default()));
    }
    if raw.len() as u64 > MAX_RECORD_LEN {
        return Ok(None);
    }
    Ok(std::str::from_utf8(&raw).ok().and_then(Record::parse))
}

fn damaged(dir: &Path, user: &str) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!(
            "{} is damaged (expected \"<failures> <last time>\")",
            dir.join(user).display()
        ),
    )
}

/// A missing file means no failures (first use, or after a reset); a damaged
/// one is an `InvalidData` error, never "no failures".
pub fn load(dir: &Path, user: &str) -> io::Result<Record> {
    match open_locked(dir, user, false)? {
        Some(mut file) => read_record(&mut file)?.ok_or_else(|| damaged(dir, user)),
        None => Ok(Record::default()),
    }
}

/// [`load`] for the check before a scan: creates the directory and an empty
/// counter when missing and opens it for writing under the lock, so an error
/// also means a failure could not be recorded. [`reset`] removes the file.
pub fn load_or_create(dir: &Path, user: &str) -> io::Result<Record> {
    let mut file = open_locked(dir, user, true)?.expect("created");
    read_record(&mut file)?.ok_or_else(|| damaged(dir, user))
}

pub fn record_failure(dir: &Path, user: &str, now: u64) -> io::Result<Record> {
    let mut file = open_locked(dir, user, true)?.expect("created");
    // Damaged content says nothing trustworthy about earlier failures, so this
    // failure starts a fresh count and the rewrite below repairs the file. PAM
    // refuses face login while the counter is damaged, so only damage that
    // appears during a scan gets here.
    let previous = read_record(&mut file)?.unwrap_or_default().current(now);
    let record = Record {
        failures: previous.failures.saturating_add(1),
        last: now,
    };
    // One write over the old record, then trim: a failed write leaves the old
    // count, never an empty file, which would read as no failures.
    let line = format!("{} {}\n", record.failures, record.last);
    file.rewind()?;
    file.write_all(line.as_bytes())?;
    file.set_len(line.len() as u64)?;
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
        // Damaged content is an error naming the file, never "no failures".
        let overlong = format!("3 1000{}junk\n", " ".repeat(60));
        let damaged: &[&[u8]] = &[
            b"garbage here too\n",
            b"\n",
            b"3\n",
            b"3 1000 7\n",
            b"-1 1000\n",
            b"4294967296 1000\n",
            b"\xff\xfe 1000\n",
            overlong.as_bytes(),
        ];
        for content in damaged {
            fs::write(d.join("carol"), content).unwrap();
            let error = load(&d, "carol").unwrap_err();
            let shown = String::from_utf8_lossy(content);
            assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{shown:?}");
            assert!(
                error
                    .to_string()
                    .contains(&d.join("carol").display().to_string()),
                "{error}"
            );
        }
        // A missing file still means no failures, and so does an empty one:
        // it was created before any failure was written.
        assert_eq!(load(&d, "dave").unwrap(), Record::default());
        fs::write(d.join("carol"), "").unwrap();
        assert_eq!(load(&d, "carol").unwrap(), Record::default());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn a_failure_on_a_damaged_counter_starts_a_fresh_count() {
        let d = dir("fresh");
        fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        let overlong = format!("3 4900{}junk\n", " ".repeat(60));
        let damaged: &[&[u8]] = &[b"garbage\n", b"\xff\xfe\n", overlong.as_bytes()];
        let fresh = Record {
            failures: 1,
            last: 5000,
        };
        for content in damaged {
            fs::write(d.join("carol"), content).unwrap();
            let shown = String::from_utf8_lossy(content);
            assert!(load(&d, "carol").is_err(), "{shown:?}");
            assert_eq!(
                record_failure(&d, "carol", 5000).unwrap(),
                fresh,
                "{shown:?}"
            );
            // The rewrite repairs the file.
            assert_eq!(load(&d, "carol").unwrap(), fresh, "{shown:?}");
        }
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn load_or_create_proves_that_failures_can_be_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("create");
        // Directory and counter are created; the empty counter means no failures.
        assert_eq!(load_or_create(&d, "alice").unwrap(), Record::default());
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
        let counter = fs::metadata(d.join("alice")).unwrap();
        assert_eq!((counter.len(), counter.mode() & 0o777), (0, 0o600));
        assert_eq!(load(&d, "alice").unwrap(), Record::default());
        let record = record_failure(&d, "alice", 50).unwrap();
        assert_eq!(load_or_create(&d, "alice").unwrap(), record);
        fs::write(d.join("alice"), "garbage\n").unwrap();
        let error = load_or_create(&d, "alice").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        // Where no failure could be recorded, `load` alone sees "no failures".
        let open = d.join("open");
        fs::DirBuilder::new().mode(0o700).create(&open).unwrap();
        fs::set_permissions(&open, fs::Permissions::from_mode(0o777)).unwrap();
        let dangling = d.join("dangling");
        std::os::unix::fs::symlink(d.join("nowhere"), &dangling).unwrap();
        let mut unusable = vec![open, dangling];
        // Root ignores directory permissions; nobody else can write here.
        if unsafe { libc::geteuid() } != 0 {
            let read_only = d.join("read-only");
            fs::DirBuilder::new()
                .mode(0o500)
                .create(&read_only)
                .unwrap();
            unusable.push(read_only);
        }
        for place in &unusable {
            assert_eq!(load(place, "bob").unwrap(), Record::default());
            assert!(record_failure(place, "bob", 60).is_err());
            assert!(load_or_create(place, "bob").is_err(), "{}", place.display());
        }
        let _ = fs::remove_dir_all(d);
    }
}
