//! Pause face login after repeated failed face attempts, or after repeated
//! scans that saw no face although a head-turn challenge was asked for.
//!
//! A root-only file per user under [`STATE_DIR`] holds
//! `"<failures> <last time> <no-face scans> <last no-face time>"` (versions
//! before the no-face streak wrote the first two fields only, which still
//! load); it is empty from its creation until the first count is written.
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
/// Scans in a row that saw no face after a head-turn challenge was asked for.
/// Slower than the failed-attempt limit, so a user who steps away from the
/// camera for a moment is not paused, while an attacker can no longer wait
/// for the sequence their recording shows by hiding it for free.
pub const MAX_NO_FACE_SCANS: u32 = 10;
/// Twice the longest record (64 bytes); longer content was not written here.
const MAX_RECORD_LEN: u64 = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Record {
    pub failures: u32,
    pub last: u64,
    /// Scans without a face after a head-turn challenge, and the last one.
    pub no_face: u32,
    pub no_face_last: u64,
}

/// Why face login is paused, with the count that reached its limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PauseCause {
    FailedFaces(u32),
    NoFace(u32),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pause {
    pub until: u64,
    pub cause: PauseCause,
}

impl Record {
    /// `None` for anything but two or four unsigned numbers.
    fn parse(raw: &str) -> Option<Record> {
        let fields: Vec<&str> = raw.split_whitespace().collect();
        let count = |i: usize| fields[i].parse::<u32>().ok();
        let time = |i: usize| fields[i].parse::<u64>().ok();
        match fields.len() {
            2 => Some(Record {
                failures: count(0)?,
                last: time(1)?,
                ..Record::default()
            }),
            4 => Some(Record {
                failures: count(0)?,
                last: time(1)?,
                no_face: count(2)?,
                no_face_last: time(3)?,
            }),
            _ => None,
        }
    }

    fn line(self) -> String {
        format!(
            "{} {} {} {}\n",
            self.failures, self.last, self.no_face, self.no_face_last
        )
    }

    /// Each streak ends [`LOCKOUT`] after its last count.
    pub fn current(self, now: u64) -> Record {
        let expired = |last: u64| now.saturating_sub(last) >= LOCKOUT.as_secs();
        let mut out = self;
        if expired(self.last) {
            (out.failures, out.last) = (0, 0);
        }
        if expired(self.no_face_last) {
            (out.no_face, out.no_face_last) = (0, 0);
        }
        out
    }

    /// The pause in force, if any; the later one when both limits are reached.
    /// `max_failures` 0 turns both limits off.
    pub fn pause(self, now: u64, max_failures: u32) -> Option<Pause> {
        if max_failures == 0 {
            return None;
        }
        let current = self.current(now);
        let failed = (current.failures >= max_failures).then(|| Pause {
            until: current.last + LOCKOUT.as_secs(),
            cause: PauseCause::FailedFaces(current.failures),
        });
        let no_face = (current.no_face >= MAX_NO_FACE_SCANS).then(|| Pause {
            until: current.no_face_last + LOCKOUT.as_secs(),
            cause: PauseCause::NoFace(current.no_face),
        });
        failed.into_iter().chain(no_face).max_by_key(|p| p.until)
    }

    pub fn locked_until(self, now: u64, max_failures: u32) -> Option<u64> {
        self.pause(now, max_failures).map(|p| p.until)
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
    open_locked_as(dir, user, create, libc::LOCK_EX)
}

/// `lock` is `LOCK_EX`, or `LOCK_EX | LOCK_NB` for an error of kind
/// `WouldBlock` while someone else holds it.
fn open_locked_as(
    dir: &Path,
    user: &str,
    create: bool,
    lock: libc::c_int,
) -> io::Result<Option<fs::File>> {
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
    if unsafe { libc::flock(file.as_raw_fd(), lock) } != 0 {
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
            "{} is damaged (expected \"<failures> <last time> <no-face scans> <last no-face time>\")",
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

/// A scan in progress: holds the counter's lock from the check before the
/// scan until its result is recorded, so concurrent attempts for one user
/// cannot all pass the check before any of them counts.
#[derive(Debug)]
pub struct ScanGuard {
    file: fs::File,
    path: PathBuf,
}

#[derive(Debug)]
pub enum ScanStart {
    /// The counter is locked for this scan; the record is its current state.
    Ready(ScanGuard, Record),
    /// Another face scan for this user holds the counter.
    Busy,
}

/// [`load`] for the check before a scan: creates the directory and an empty
/// counter when missing and locks it for writing without waiting, so an error
/// also means a failure could not be recorded. [`reset`] removes the file.
pub fn begin_scan(dir: &Path, user: &str) -> io::Result<ScanStart> {
    let mut file = match open_locked_as(dir, user, true, libc::LOCK_EX | libc::LOCK_NB) {
        Ok(file) => file.expect("created"),
        Err(e) if e.kind() == io::ErrorKind::WouldBlock => return Ok(ScanStart::Busy),
        Err(e) => return Err(e),
    };
    let record = read_record(&mut file)?.ok_or_else(|| damaged(dir, user))?;
    Ok(ScanStart::Ready(
        ScanGuard {
            file,
            path: state_file(dir, user)?,
        },
        record,
    ))
}

fn count_failure(record: &mut Record, now: u64) {
    record.failures = record.failures.saturating_add(1);
    record.last = now;
}

fn count_no_face(record: &mut Record, now: u64) {
    record.no_face = record.no_face.saturating_add(1);
    record.no_face_last = now;
}

impl ScanGuard {
    pub fn record_failure(&mut self, now: u64) -> io::Result<Record> {
        self.record(now, count_failure)
    }

    /// See [`record_no_face`].
    pub fn record_no_face(&mut self, now: u64) -> io::Result<Record> {
        self.record(now, count_no_face)
    }

    /// Counts into the locked file. A password login during the scan removes
    /// that file ([`reset`]); the count then goes into the counter now at the
    /// path, so the scan is not lost in a deleted file. If another scan holds
    /// that new counter, this count is dropped rather than waited for.
    fn record(&mut self, now: u64, count: fn(&mut Record, u64)) -> io::Result<Record> {
        let record = update_file(&mut self.file, now, |record| count(record, now))?;
        if self.still_linked()? {
            return Ok(record);
        }
        let (Some(dir), Some(user)) = (self.path.parent(), self.path.file_name()) else {
            return Ok(record);
        };
        let user = user.to_string_lossy();
        match open_locked_as(dir, &user, true, libc::LOCK_EX | libc::LOCK_NB) {
            Ok(Some(mut file)) => update_file(&mut file, now, |record| count(record, now)),
            Ok(None) => Ok(record),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => Ok(record),
            Err(e) => Err(e),
        }
    }

    /// Whether the path still names the file this guard holds.
    fn still_linked(&self) -> io::Result<bool> {
        let held = self.file.metadata()?;
        match fs::symlink_metadata(&self.path) {
            Ok(now) => Ok(now.ino() == held.ino() && now.dev() == held.dev()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(e),
        }
    }

    /// A successful face login: removed while still locked.
    pub fn reset(self) -> io::Result<()> {
        match fs::remove_file(&self.path) {
            Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
            _ => Ok(()),
        }
    }
}

pub fn record_failure(dir: &Path, user: &str, now: u64) -> io::Result<Record> {
    update(dir, user, now, |record| count_failure(record, now))
}

/// A scan that saw no face after a head-turn challenge was asked for. It
/// leaves the failed-attempt count alone, and a rejected face does not end
/// this streak; only [`reset`] (a face or password login) or time does.
pub fn record_no_face(dir: &Path, user: &str, now: u64) -> io::Result<Record> {
    update(dir, user, now, |record| count_no_face(record, now))
}

fn update(dir: &Path, user: &str, now: u64, count: impl FnOnce(&mut Record)) -> io::Result<Record> {
    let mut file = open_locked(dir, user, true)?.expect("created");
    update_file(&mut file, now, count)
}

/// Rewrites a counter the caller holds locked.
fn update_file(
    file: &mut fs::File,
    now: u64,
    count: impl FnOnce(&mut Record),
) -> io::Result<Record> {
    file.rewind()?;
    // Damaged content says nothing trustworthy about earlier counts, so this
    // one starts afresh and the rewrite below repairs the file. PAM refuses
    // face login while the counter is damaged, so only damage that appears
    // during a scan gets here.
    let mut record = read_record(file)?.unwrap_or_default().current(now);
    count(&mut record);
    // One write over the old record, then trim: a failed write leaves the old
    // counts, never an empty file, which would read as no failures.
    let line = record.line();
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

    /// The record a scan starts from; the guard is released at once.
    fn ready(dir: &Path, user: &str) -> Record {
        match begin_scan(dir, user).unwrap() {
            ScanStart::Ready(_, record) => record,
            ScanStart::Busy => panic!("busy"),
        }
    }

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
    fn scans_without_a_face_pause_after_their_own_slower_limit() {
        let d = dir("no-face");
        let t = 1_000_000;
        for i in 1..MAX_NO_FACE_SCANS {
            let r = record_no_face(&d, "alice", t + u64::from(i)).unwrap();
            assert_eq!((r.no_face, r.failures), (i, 0));
            // Stepping away for a while never pauses face login.
            assert_eq!(r.pause(t + u64::from(i), 5), None, "{i}");
        }
        // A rejected face counts on its own and does not end the streak.
        let r = record_failure(&d, "alice", t + 20).unwrap();
        assert_eq!((r.failures, r.no_face), (1, MAX_NO_FACE_SCANS - 1));
        let r = record_no_face(&d, "alice", t + 30).unwrap();
        assert_eq!(
            r.pause(t + 30, 5),
            Some(Pause {
                until: t + 30 + LOCKOUT.as_secs(),
                cause: PauseCause::NoFace(MAX_NO_FACE_SCANS),
            })
        );
        assert_eq!(r.locked_until(t + 30, 5), Some(t + 30 + LOCKOUT.as_secs()));
        assert_eq!(load(&d, "alice").unwrap(), r, "stored");
        // 0 turns every limit off.
        assert_eq!(r.pause(t + 30, 0), None);
        // The streak expires like the failed-attempt count.
        let later = t + 30 + LOCKOUT.as_secs();
        assert_eq!(r.pause(later, 5), None);
        assert_eq!(record_no_face(&d, "alice", later).unwrap().no_face, 1);
        // A success or password login clears both streaks.
        reset(&d, "alice").unwrap();
        assert_eq!(load(&d, "alice").unwrap(), Record::default());
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn the_later_pause_wins_and_old_counters_still_load() {
        let d = dir("both");
        fs::DirBuilder::new().mode(0o700).create(&d).unwrap();
        // Written by a version without the no-face streak.
        fs::write(d.join("alice"), "5 1000\n").unwrap();
        let old = load(&d, "alice").unwrap();
        assert_eq!(
            old,
            Record {
                failures: 5,
                last: 1000,
                ..Record::default()
            }
        );
        assert_eq!(
            old.pause(1000, 5).map(|p| p.cause),
            Some(PauseCause::FailedFaces(5))
        );
        let both = Record {
            failures: 5,
            last: 1000,
            no_face: MAX_NO_FACE_SCANS,
            no_face_last: 1100,
        };
        assert_eq!(
            both.pause(1100, 5),
            Some(Pause {
                until: 1100 + LOCKOUT.as_secs(),
                cause: PauseCause::NoFace(MAX_NO_FACE_SCANS)
            })
        );
        // The rewrite keeps both streaks.
        let r = record_no_face(&d, "alice", 1001).unwrap();
        assert_eq!((r.failures, r.no_face), (5, 1));
        assert_eq!(
            fs::read_to_string(d.join("alice")).unwrap(),
            "5 1000 1 1001\n"
        );
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn one_scan_at_a_time_records_through_its_own_lock() {
        let d = dir("guard");
        let ScanStart::Ready(mut guard, record) = begin_scan(&d, "alice").unwrap() else {
            panic!("busy")
        };
        assert_eq!(record, Record::default());
        // A second attempt for the same user while the first is scanning.
        assert!(matches!(begin_scan(&d, "alice").unwrap(), ScanStart::Busy));
        // Other users are not affected.
        assert!(matches!(
            begin_scan(&d, "bob").unwrap(),
            ScanStart::Ready(..)
        ));
        assert_eq!(guard.record_failure(10).unwrap().failures, 1);
        assert_eq!(guard.record_no_face(11).unwrap().no_face, 1);
        drop(guard);
        let r = ready(&d, "alice");
        assert_eq!((r.failures, r.no_face), (1, 1));
        // The next scan sees both counts and can clear them on success.
        let ScanStart::Ready(guard, _) = begin_scan(&d, "alice").unwrap() else {
            panic!("busy")
        };
        guard.reset().unwrap();
        assert!(!d.join("alice").exists());
        assert!(matches!(
            begin_scan(&d, "alice").unwrap(),
            ScanStart::Ready(..)
        ));
        let _ = fs::remove_dir_all(d);
    }

    /// A password login (`reset`) while a scan runs must not swallow the
    /// failure that scan records afterwards.
    #[test]
    fn a_failure_recorded_after_a_reset_lands_in_the_new_counter() {
        let d = dir("relink");
        record_failure(&d, "alice", 5).unwrap();
        let ScanStart::Ready(mut guard, record) = begin_scan(&d, "alice").unwrap() else {
            panic!("busy")
        };
        assert_eq!(record.failures, 1);
        reset(&d, "alice").unwrap();
        assert!(!d.join("alice").exists());
        // The old count went with the old file; this failure starts the new
        // counter, and the guard reports that counter.
        let counted = guard.record_failure(10).unwrap();
        assert_eq!(
            counted,
            Record {
                failures: 1,
                last: 10,
                ..Record::default()
            }
        );
        assert_eq!(
            load(&d, "alice").unwrap(),
            counted,
            "in the counter at the path"
        );
        // While nothing replaced the file, the held one is the one at the path.
        let ScanStart::Ready(mut guard, _) = begin_scan(&d, "bob").unwrap() else {
            panic!("busy")
        };
        guard.record_no_face(11).unwrap();
        drop(guard);
        assert_eq!(load(&d, "bob").unwrap().no_face, 1);
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
        let overlong = format!("3 1000{}junk\n", " ".repeat(130));
        let damaged: &[&[u8]] = &[
            b"garbage here too\n",
            b"\n",
            b"3\n",
            b"3 1000 7\n",
            b"3 1000 7 1000 1\n",
            b"3 1000 x 1000\n",
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
        let overlong = format!("3 4900{}junk\n", " ".repeat(130));
        let damaged: &[&[u8]] = &[b"garbage\n", b"\xff\xfe\n", overlong.as_bytes()];
        let fresh = Record {
            failures: 1,
            last: 5000,
            ..Record::default()
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
    fn begin_scan_proves_that_failures_can_be_recorded() {
        use std::os::unix::fs::PermissionsExt;
        let d = dir("create");
        // Directory and counter are created; the empty counter means no failures.
        assert_eq!(ready(&d, "alice"), Record::default());
        assert_eq!(fs::metadata(&d).unwrap().mode() & 0o777, 0o700);
        let counter = fs::metadata(d.join("alice")).unwrap();
        assert_eq!((counter.len(), counter.mode() & 0o777), (0, 0o600));
        assert_eq!(load(&d, "alice").unwrap(), Record::default());
        let record = record_failure(&d, "alice", 50).unwrap();
        assert_eq!(ready(&d, "alice"), record);
        fs::write(d.join("alice"), "garbage\n").unwrap();
        let error = begin_scan(&d, "alice").unwrap_err();
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
            assert!(begin_scan(place, "bob").is_err(), "{}", place.display());
        }
        let _ = fs::remove_dir_all(d);
    }
}
