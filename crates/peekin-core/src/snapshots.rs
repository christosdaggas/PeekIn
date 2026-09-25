//! Photos of failed face attempts (`[snapshots] save_failed`, opt-in).
//! The worker keeps one JPEG per attempt where a face was rejected in
//! [`SNAPSHOT_DIR`] (0700, worker account); the newest `keep` files of each
//! account remain, so attempts on one account never push out another's.

use crate::paths::validate_username;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};

pub const SNAPSHOT_DIR: &str = "/var/log/peekin";
pub const DEFAULT_KEEP: u32 = 20;
pub const MAX_KEEP: u32 = 100;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Snapshot {
    pub time: u64,
    pub user: String,
    pub path: PathBuf,
}

fn file_name(time: u64, user: &str) -> String {
    format!("{time:012}-{user}.jpg")
}

fn parse(path: &Path) -> Option<Snapshot> {
    let name = path.file_name()?.to_str()?;
    let (time, user) = name.strip_suffix(".jpg")?.split_once('-')?;
    if time.len() != 12 || !time.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    validate_username(user).ok()?;
    Some(Snapshot {
        time: time.parse().ok()?,
        user: user.to_string(),
        path: path.to_path_buf(),
    })
}

pub fn list_all(dir: &Path) -> io::Result<Vec<Snapshot>> {
    let mut out = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if entry.file_type()?.is_file() {
            if let Some(snapshot) = parse(&entry.path()) {
                out.push(snapshot);
            }
        }
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub fn list(dir: &Path, user: &str) -> io::Result<Vec<Snapshot>> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    Ok(list_all(dir)?
        .into_iter()
        .filter(|s| s.user == user)
        .collect())
}

/// Store `jpeg`, then delete `user`'s oldest photos beyond `keep`.
pub fn save(dir: &Path, user: &str, time: u64, jpeg: &[u8], keep: u32) -> io::Result<PathBuf> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let path = dir.join(file_name(time, user));
    // create_new also refuses to follow a planted symlink.
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&path)?;
    file.write_all(jpeg)?;
    file.sync_all()?;
    let mine = list(dir, user)?;
    let keep = keep.clamp(1, MAX_KEEP) as usize;
    for old in &mine[..mine.len().saturating_sub(keep)] {
        fs::remove_file(&old.path)?;
    }
    Ok(path)
}

pub fn clear(dir: &Path, user: &str) -> io::Result<usize> {
    let mine = list(dir, user)?;
    for snapshot in &mine {
        fs::remove_file(&snapshot.path)?;
    }
    Ok(mine.len())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dir(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("peekin-snap-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn saves_lists_and_keeps_only_the_newest_of_each_user() {
        let d = dir("keep");
        save(&d, "bob", 1_790_000_000, b"jpeg", 3).unwrap();
        for t in 1..=5 {
            save(&d, "alice", 1_790_000_000 + t, b"jpeg", 3).unwrap();
        }
        // alice's attempts never push out bob's photo, nor bob's hers.
        let bob = list(&d, "bob").unwrap();
        assert_eq!(bob.len(), 1, "{bob:?}");
        save(&d, "bob", 1_790_000_010, b"jpeg", 3).unwrap();
        let alice = list(&d, "alice").unwrap();
        assert_eq!(
            alice.iter().map(|s| s.time).collect::<Vec<_>>(),
            [1_790_000_003, 1_790_000_004, 1_790_000_005]
        );
        assert_eq!(fs::read(&alice[0].path).unwrap(), b"jpeg");
        assert_eq!(list(&d, "bob").unwrap().len(), 2);
        assert_eq!(list_all(&d).unwrap().len(), 5);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn clear_removes_only_that_users_photos() {
        let d = dir("clear");
        save(&d, "alice", 1, b"a", 10).unwrap();
        save(&d, "bob", 2, b"b", 10).unwrap();
        assert_eq!(clear(&d, "alice").unwrap(), 1);
        assert!(list(&d, "alice").unwrap().is_empty());
        assert_eq!(list(&d, "bob").unwrap().len(), 1);
        let _ = fs::remove_dir_all(d);
    }

    #[test]
    fn foreign_files_and_bad_names_are_ignored_or_refused() {
        let d = dir("names");
        fs::write(d.join("notes.txt"), "x").unwrap();
        fs::write(d.join("123-alice.jpg"), "short time").unwrap();
        fs::write(d.join("000000000001-.hidden.jpg"), "x").unwrap();
        assert!(list_all(&d).unwrap().is_empty());
        assert!(save(&d, "../etc", 1, b"x", 5).is_err());
        assert!(list(&d, "a/b").is_err());
        save(&d, "alice", 7, b"x", 5).unwrap();
        assert!(save(&d, "alice", 7, b"x", 5).is_err(), "never overwrites");
        let _ = fs::remove_dir_all(d);
    }
}
