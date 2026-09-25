//! `peekin config`: the editor runs as the account that called sudo, on a
//! private copy; root only reads that copy back and applies it through
//! [`peekin_core::management::replace_config`]. Running the editor as root
//! would hand out a root shell (every editor can run commands).

use anyhow::{anyhow, bail, Context, Result};
use std::ffi::{CStr, CString, OsString};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus};

/// Larger than any config.ini; a bigger copy is refused, not cut off.
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const COPY_NAME: &str = "config.ini";
/// Passed on to the editor; everything else is dropped.
const KEPT_ENV: &[&str] = &[
    "TERM",
    "COLORTERM",
    "LANG",
    "LANGUAGE",
    "LC_ALL",
    "LC_CTYPE",
    "LC_MESSAGES",
    "LC_COLLATE",
    "DISPLAY",
    "WAYLAND_DISPLAY",
];
const DEFAULT_PATH: &str = "/usr/local/bin:/usr/bin:/bin";

/// The account that ran `sudo peekin config`.
#[derive(Debug)]
pub struct Invoker {
    pub name: String,
    pub uid: libc::uid_t,
    pub gid: libc::gid_t,
    groups: Vec<libc::gid_t>,
    home: OsString,
    shell: OsString,
}

impl Invoker {
    /// `SUDO_USER`, which must name an account other than root. There is no
    /// other source: without it nobody is known to edit as, and root is refused.
    pub fn from_env() -> Result<Self> {
        let name = std::env::var("SUDO_USER")
            .ok()
            .filter(|n| !n.is_empty())
            .ok_or_else(|| {
                anyhow!(
                    "SUDO_USER is not set: run 'sudo peekin config' from your own account, \
                     so that the editor runs as you and not as root \
                     (or change single settings with 'peekin set')"
                )
            })?;
        peekin_core::paths::validate_username(&name)?;
        let invoker = Self::lookup(&name)?;
        if invoker.uid == 0 {
            bail!(
                "SUDO_USER is root: run 'sudo peekin config' from your own account, \
                 so that the editor does not run as root"
            );
        }
        Ok(invoker)
    }

    fn lookup(name: &str) -> Result<Self> {
        let c_name = CString::new(name)?;
        let mut pwd: libc::passwd = unsafe { std::mem::zeroed() };
        let mut buf = vec![0 as libc::c_char; 16 * 1024];
        let mut result = std::ptr::null_mut();
        // SAFETY: all pointers reference live, correctly sized buffers.
        let rc = unsafe {
            libc::getpwnam_r(
                c_name.as_ptr(),
                &mut pwd,
                buf.as_mut_ptr(),
                buf.len(),
                &mut result,
            )
        };
        if rc != 0 || result.is_null() || pwd.pw_dir.is_null() || pwd.pw_shell.is_null() {
            bail!("SUDO_USER {name:?} is not an account on this system");
        }
        // SAFETY: on success these point into `buf`, NUL-terminated.
        let (home, shell) = unsafe {
            (
                OsString::from(std::ffi::OsStr::from_bytes(
                    CStr::from_ptr(pwd.pw_dir).to_bytes(),
                )),
                OsString::from(std::ffi::OsStr::from_bytes(
                    CStr::from_ptr(pwd.pw_shell).to_bytes(),
                )),
            )
        };
        let mut count: libc::c_int = 0;
        // SAFETY: a null buffer with count 0 only asks for the number of groups.
        unsafe {
            libc::getgrouplist(
                c_name.as_ptr(),
                pwd.pw_gid,
                std::ptr::null_mut(),
                &mut count,
            )
        };
        if !(1..=65_536).contains(&count) {
            bail!("cannot resolve the groups of {name}");
        }
        let mut groups = vec![pwd.pw_gid; count as usize];
        // SAFETY: `groups` holds `count` entries.
        if unsafe {
            libc::getgrouplist(c_name.as_ptr(), pwd.pw_gid, groups.as_mut_ptr(), &mut count)
        } < 0
        {
            bail!("cannot resolve the groups of {name}");
        }
        groups.truncate(count as usize);
        Ok(Self {
            name: name.to_string(),
            uid: pwd.pw_uid,
            gid: pwd.pw_gid,
            groups,
            home,
            shell,
        })
    }
}

/// A copy of config.ini in a fresh directory owned by the invoker; the
/// directory is removed on drop.
pub struct Staged {
    dir: PathBuf,
    file: PathBuf,
}

impl Staged {
    /// Written by root before the invoker owns the directory, so nothing of
    /// theirs can be in the way.
    pub fn new(contents: &str, invoker: &Invoker) -> Result<Self> {
        let template = std::env::temp_dir().join("peekin-config.XXXXXX");
        let mut template = CString::new(template.as_os_str().as_bytes())?.into_bytes_with_nul();
        // SAFETY: a writable, NUL-terminated template ending in XXXXXX.
        if unsafe { libc::mkdtemp(template.as_mut_ptr().cast()) }.is_null() {
            return Err(std::io::Error::last_os_error()).context("cannot create a private copy");
        }
        template.pop();
        let dir = PathBuf::from(std::ffi::OsStr::from_bytes(&template));
        let staged = Self {
            file: dir.join(COPY_NAME),
            dir,
        };
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&staged.file)
            .context("cannot create a private copy")?;
        file.write_all(contents.as_bytes())?;
        file.sync_all()?;
        chown(&file, invoker)?;
        let dir = File::open(&staged.dir)?;
        chown(&dir, invoker)?;
        Ok(staged)
    }

    /// Run `editor` on the copy as `invoker`, with a minimal environment.
    pub fn edit(&self, editor: &Path, invoker: &Invoker) -> Result<ExitStatus> {
        let mut command = Command::new(editor);
        command
            .arg(&self.file)
            .current_dir(&self.dir)
            .env_clear()
            .env("HOME", &invoker.home)
            .env("SHELL", &invoker.shell)
            .env("USER", &invoker.name)
            .env("LOGNAME", &invoker.name)
            .env(
                "PATH",
                std::env::var_os("PATH").unwrap_or_else(|| DEFAULT_PATH.into()),
            );
        for name in KEPT_ENV {
            if let Some(value) = std::env::var_os(name) {
                command.env(name, value);
            }
        }
        let (uid, gid, groups) = (invoker.uid, invoker.gid, invoker.groups.clone());
        // SAFETY: only async-signal-safe calls between fork and exec.
        unsafe {
            command.pre_exec(move || {
                if libc::geteuid() == 0
                    && (libc::setgroups(groups.len(), groups.as_ptr()) != 0
                        || libc::setgid(gid) != 0
                        || libc::setuid(uid) != 0)
                {
                    return Err(std::io::Error::last_os_error());
                }
                // Also refuses a non-root caller editing as somebody else.
                if libc::getuid() != uid
                    || libc::geteuid() != uid
                    || libc::getegid() != gid
                    || libc::setuid(0) == 0
                {
                    return Err(std::io::Error::from_raw_os_error(libc::EPERM));
                }
                Ok(())
            });
        }
        command
            .status()
            .with_context(|| format!("cannot run {} as {}", editor.display(), invoker.name))
    }

    /// The edited copy: a regular file of the invoker with one link, never
    /// followed through a symlink, so root reads nothing else in its place.
    pub fn read(&self, invoker: &Invoker) -> Result<String> {
        let file = OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
            .open(&self.file)
            .with_context(|| {
                format!(
                    "cannot read the edited copy {} (it must stay a regular file)",
                    self.file.display()
                )
            })?;
        check_copy(&file.metadata()?, invoker.uid)?;
        let mut raw = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut raw)?;
        if raw.len() as u64 > MAX_CONFIG_BYTES {
            bail!("the edited copy is larger than {MAX_CONFIG_BYTES} bytes");
        }
        String::from_utf8(raw).map_err(|_| anyhow!("the edited copy is not UTF-8 text"))
    }
}

impl Drop for Staged {
    fn drop(&mut self) {
        // Does not follow symlinks the invoker may have left inside.
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn chown(file: &File, invoker: &Invoker) -> Result<()> {
    // SAFETY: fchown on a descriptor we own.
    if unsafe { libc::geteuid() } == 0
        && unsafe { libc::fchown(file.as_raw_fd(), invoker.uid, invoker.gid) } != 0
    {
        return Err(std::io::Error::last_os_error()).context("cannot hand the copy over");
    }
    Ok(())
}

fn check_copy(meta: &fs::Metadata, uid: libc::uid_t) -> Result<()> {
    if !meta.is_file() {
        bail!("the edited copy is no longer a regular file");
    }
    if meta.uid() != uid || meta.nlink() != 1 {
        bail!("the edited copy was replaced by a file that is not the editor's own");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn me() -> Invoker {
        let uid = unsafe { libc::geteuid() };
        Invoker {
            name: "tester".into(),
            uid,
            gid: unsafe { libc::getegid() },
            groups: Vec::new(),
            home: "/nonexistent".into(),
            shell: "/bin/sh".into(),
        }
    }

    #[test]
    fn the_copy_is_private_and_removed_on_drop() {
        let staged = Staged::new("[core]\n", &me()).unwrap();
        let dir = staged.dir.clone();
        let meta = fs::metadata(&staged.file).unwrap();
        assert_eq!(meta.mode() & 0o777, 0o600);
        assert_eq!(fs::metadata(&dir).unwrap().mode() & 0o777, 0o700);
        assert_eq!(staged.read(&me()).unwrap(), "[core]\n");
        drop(staged);
        assert!(!dir.exists());
    }

    #[test]
    fn links_foreign_files_and_oversized_copies_are_refused() {
        let invoker = me();
        let staged = Staged::new("", &invoker).unwrap();
        let other = staged.dir.join("other");
        fs::write(&other, "secret").unwrap();
        // A hard link: two names for one file.
        fs::remove_file(&staged.file).unwrap();
        fs::hard_link(&other, &staged.file).unwrap();
        assert!(staged.read(&invoker).is_err());
        // A symlink is never followed.
        fs::remove_file(&staged.file).unwrap();
        std::os::unix::fs::symlink(&other, &staged.file).unwrap();
        let error = staged.read(&invoker).unwrap_err().to_string();
        assert!(!error.contains("secret"), "{error}");
        // A FIFO would block a plain open.
        fs::remove_file(&staged.file).unwrap();
        let fifo = CString::new(staged.file.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(fifo.as_ptr(), 0o600) }, 0);
        assert!(staged.read(&invoker).is_err());
        fs::remove_file(&staged.file).unwrap();
        fs::write(&staged.file, vec![b'#'; MAX_CONFIG_BYTES as usize + 1]).unwrap();
        assert!(staged.read(&invoker).is_err());
        // Another owner.
        fs::write(&staged.file, "[core]\n").unwrap();
        let stranger = Invoker {
            uid: invoker.uid.wrapping_add(1),
            ..me()
        };
        assert!(staged.read(&stranger).is_err());
        assert!(staged.read(&invoker).is_ok());
    }
}
