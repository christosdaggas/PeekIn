//! History of face login attempts, one file per user in [`ACTIVITY_DIR`].
//! Files are root-owned 0600 with an ACL letting their user read them; the
//! directory is 0711. Never used for authentication decisions.

use crate::paths::validate_username;
use serde::{Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Seek, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

pub const ACTIVITY_DIR: &str = "/var/lib/peekin-activity";
/// Entries kept per user; older ones are dropped.
pub const MAX_ENTRIES: usize = 200;
/// Read limit, whatever the file has grown to.
const MAX_BYTES: u64 = 256 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Outcome {
    Success,
    Rejected,
    ChallengeFailed,
    NoFace,
    /// Too dark, camera unavailable, or the scan did not finish.
    Unavailable,
    /// Skipped: face login is paused after failed attempts.
    Paused,
}

impl Outcome {
    /// Someone's face was seen and not accepted (what the away notice counts).
    pub fn is_failed_face(self) -> bool {
        matches!(self, Self::Rejected | Self::ChallengeFailed)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Entry {
    pub time: u64,
    pub service: String,
    pub outcome: Outcome,
    /// Model that matched (successes only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<i64>,
}

fn file(dir: &Path, user: &str) -> io::Result<PathBuf> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(dir.join(user))
}

fn parse(raw: &str) -> Vec<Entry> {
    raw.lines()
        .filter_map(|line| serde_json::from_str(line).ok())
        .collect()
}

pub fn read(dir: &Path, user: &str) -> io::Result<Vec<Entry>> {
    let path = file(dir, user)?;
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(&path)
    {
        Ok(file) => file,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let mut raw = String::new();
    file.take(MAX_BYTES).read_to_string(&mut raw)?;
    Ok(parse(&raw))
}

/// ACL xattr: user::rw- user:uid:r-- group::--- mask::r-- other::---
fn read_acl(uid: u32) -> Vec<u8> {
    const ENTRIES: [(u16, u16, u32); 5] = [
        (0x01, 6, u32::MAX), // ACL_USER_OBJ
        (0x02, 4, 0),        // ACL_USER, id filled in below
        (0x04, 0, u32::MAX), // ACL_GROUP_OBJ
        (0x10, 4, u32::MAX), // ACL_MASK
        (0x20, 0, u32::MAX), // ACL_OTHER
    ];
    let mut out = 2u32.to_le_bytes().to_vec();
    for (tag, perm, id) in ENTRIES {
        out.extend_from_slice(&tag.to_le_bytes());
        out.extend_from_slice(&perm.to_le_bytes());
        out.extend_from_slice(&(if tag == 0x02 { uid } else { id }).to_le_bytes());
    }
    out
}

/// Append `entry`, keeping the newest [`MAX_ENTRIES`]; `uid` may read the file.
pub fn record(dir: &Path, user: &str, uid: u32, entry: &Entry) -> io::Result<()> {
    let path = file(dir, user)?;
    let meta = fs::symlink_metadata(dir)?;
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!(
                "{} must be a root-owned directory not writable by others",
                dir.display()
            ),
        ));
    }
    let mut file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.uid() != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("{} is not a root-owned regular file", path.display()),
        ));
    }
    // SAFETY: flock on a descriptor we own; released when it is closed.
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut raw = String::new();
    (&mut file).take(MAX_BYTES).read_to_string(&mut raw)?;
    let mut entries = parse(&raw);
    entries.push(entry.clone());
    let skip = entries.len().saturating_sub(MAX_ENTRIES);
    let mut text = String::new();
    for e in &entries[skip..] {
        text.push_str(&serde_json::to_string(e).map_err(io::Error::other)?);
        text.push('\n');
    }
    file.rewind()?;
    file.set_len(0)?;
    file.write_all(text.as_bytes())?;
    // Without ACL support the file stays root-only.
    let acl = read_acl(uid);
    // SAFETY: valid descriptor, NUL-terminated name and a live buffer.
    let set = unsafe {
        libc::fsetxattr(
            file.as_raw_fd(),
            c"system.posix_acl_access".as_ptr(),
            acl.as_ptr().cast(),
            acl.len(),
            0,
        )
    };
    if set != 0 {
        return Err(io::Error::other(format!(
            "history saved, but cannot let {user} read it: {}",
            io::Error::last_os_error()
        )));
    }
    Ok(())
}

/// When each face model last matched: (model ID, unix time), newest first.
pub fn last_used(entries: &[Entry]) -> Vec<(i64, u64)> {
    let mut out: Vec<(i64, u64)> = Vec::new();
    for e in entries.iter().rev() {
        if let (Outcome::Success, Some(model)) = (e.outcome, e.model) {
            if !out.iter().any(|(m, _)| *m == model) {
                out.push((model, e.time));
            }
        }
    }
    out
}

/// Failed face attempts after `since` (unix time).
pub fn failed_since(entries: &[Entry], since: u64) -> usize {
    entries
        .iter()
        .filter(|e| e.time > since && e.outcome.is_failed_face())
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(time: u64, outcome: Outcome, model: Option<i64>) -> Entry {
        Entry {
            time,
            service: "sudo".into(),
            outcome,
            model,
        }
    }

    #[test]
    fn acl_has_the_kernel_layout() {
        let acl = read_acl(1000);
        assert_eq!(acl.len(), 4 + 5 * 8);
        assert_eq!(&acl[..4], &[2, 0, 0, 0]);
        // Second entry: ACL_USER, read, uid 1000.
        assert_eq!(&acl[12..20], &[2, 0, 4, 0, 0xe8, 0x03, 0, 0]);
    }

    #[test]
    fn history_is_read_back_and_bounded() {
        let dir = std::env::temp_dir().join(format!("peekin-activity-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        assert!(read(&dir, "alice").unwrap().is_empty());
        let path = dir.join("alice");
        // Unprivileged tests fail the owner check; parsing and helpers are tested.
        let mut text = String::new();
        for t in 0..(MAX_ENTRIES as u64 + 5) {
            text.push_str(&serde_json::to_string(&entry(t, Outcome::Rejected, None)).unwrap());
            text.push('\n');
        }
        text.push_str("not json\n");
        text.push_str(r#"{"time":999,"service":"gdm-password","outcome":"success","model":3}"#);
        fs::write(&path, text).unwrap();
        let entries = read(&dir, "alice").unwrap();
        assert_eq!(entries.len(), MAX_ENTRIES + 6);
        assert_eq!(entries.last().unwrap().model, Some(3));
        assert!(read(&dir, "../x").is_err());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn last_used_and_failures_since() {
        let entries = vec![
            entry(10, Outcome::Success, Some(1)),
            entry(20, Outcome::Rejected, None),
            entry(30, Outcome::Success, Some(2)),
            entry(40, Outcome::ChallengeFailed, None),
            entry(50, Outcome::Success, Some(1)),
            entry(60, Outcome::NoFace, None),
        ];
        assert_eq!(last_used(&entries), vec![(1, 50), (2, 30)]);
        assert_eq!(failed_since(&entries, 0), 2);
        assert_eq!(failed_since(&entries, 30), 1);
        assert_eq!(failed_since(&entries, 40), 0);
    }

    #[test]
    fn outcomes_serialise_as_kebab_case() {
        let json = serde_json::to_string(&entry(1, Outcome::ChallengeFailed, None)).unwrap();
        assert!(json.contains("\"challenge-failed\""), "{json}");
        assert!(!json.contains("model"));
    }
}
