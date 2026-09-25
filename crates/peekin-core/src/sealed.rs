//! Face models encrypted at rest with `systemd-creds` (TPM2 plus host key, or
//! the host key alone), not bound to PCRs. Everything reads the decrypted copies
//! in [`RUN_MODELS_DIR`] (tmpfs). This protects disks and backups, not against
//! root or someone holding the whole machine. Development trees stay plaintext.

use crate::models::{self, FaceModel};
use crate::paths::{validate_username, PeekinPaths};
use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

pub const RUN_MODELS_DIR: &str = "/run/peekin/models";
pub const TOOL: &str = "systemd-creds";
const SUFFIX: &str = ".dat.cred";

fn credential_name(user: &str) -> String {
    format!("peekin-model-{user}")
}

pub fn sealed_path(sealed_dir: &Path, user: &str) -> PathBuf {
    sealed_dir.join(format!("{user}{SUFFIX}"))
}

fn plain_path(dir: &Path, user: &str) -> PathBuf {
    dir.join(format!("{user}.dat"))
}

pub fn key_description() -> &'static str {
    if Path::new("/dev/tpmrm0").exists() {
        "the TPM and the host key"
    } else {
        "the host key file only (no TPM found)"
    }
}

fn run(tool: &Path, args: &[&str], input: &[u8]) -> io::Result<Vec<u8>> {
    let mut child = Command::new(tool)
        .args(args)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| io::Error::other(format!("cannot run {}: {e}", tool.display())))?;
    // A tool that fails early stops reading; its exit status says why.
    match child.stdin.take().expect("piped").write_all(input) {
        Err(e) if e.kind() != io::ErrorKind::BrokenPipe => return Err(e),
        _ => {}
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        return Err(io::Error::other(format!(
            "{} {} failed: {}",
            tool.display(),
            args.first().copied().unwrap_or_default(),
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(out.stdout)
}

/// Encrypt into `<sealed_dir>/<user>.dat.cred` (root-only, atomic).
fn seal_bytes(tool: &Path, sealed_dir: &Path, user: &str, plaintext: &[u8]) -> io::Result<()> {
    let target = sealed_path(sealed_dir, user);
    let tmp = sealed_dir.join(format!(".{user}{SUFFIX}.new"));
    let _ = fs::remove_file(&tmp);
    let name = format!("--name={}", credential_name(user));
    let tmp_arg = tmp.to_string_lossy().into_owned();
    let result = run(tool, &["encrypt", &name, "-", &tmp_arg], plaintext).and_then(|_| {
        fs::set_permissions(&tmp, fs::Permissions::from_mode(0o600))?;
        fs::rename(&tmp, &target)
    });
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn unseal_bytes(tool: &Path, sealed_dir: &Path, user: &str) -> io::Result<Vec<u8>> {
    let name = format!("--name={}", credential_name(user));
    let source = sealed_path(sealed_dir, user).to_string_lossy().into_owned();
    run(tool, &["decrypt", &name, &source, "-"], &[])
}

/// Seal `user`'s models again after a change, or delete the sealed copy when
/// none are left. No-op for development trees.
pub fn persist(paths: &PeekinPaths, user: &str) -> io::Result<()> {
    match paths.sealed_models_dir() {
        Some(sealed) => persist_with(Path::new(TOOL), paths.user_models_dir(), sealed, user),
        None => Ok(()),
    }
}

pub fn persist_with(tool: &Path, run_dir: &Path, sealed_dir: &Path, user: &str) -> io::Result<()> {
    validate_username(user).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    match fs::read(plain_path(run_dir, user)) {
        Ok(bytes) => seal_bytes(tool, sealed_dir, user, &bytes),
        Err(e) if e.kind() == io::ErrorKind::NotFound => {
            match fs::remove_file(sealed_path(sealed_dir, user)) {
                Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
                _ => Ok(()),
            }
        }
        Err(e) => Err(e),
    }
}

#[derive(Debug)]
pub struct Unsealed {
    pub user: String,
    /// The plaintext model found on disk has been sealed.
    pub migrated: bool,
    pub result: Result<(), String>,
}

fn users_with(dir: &Path, suffix: &str) -> io::Result<Vec<String>> {
    let mut users = Vec::new();
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            continue;
        }
        if let Some(user) = entry
            .file_name()
            .to_str()
            .and_then(|n| n.strip_suffix(suffix))
        {
            if validate_username(user).is_ok() && !user.contains('.') {
                users.push(user.to_string());
            }
        }
    }
    users.sort();
    Ok(users)
}

/// Decrypt every sealed model into `run_dir` (mode 0640). Plaintext models
/// still on disk are sealed first, then deleted.
pub fn unseal_all(
    tool: &Path,
    sealed_dir: &Path,
    run_dir: &Path,
    uid: libc::uid_t,
    gid: libc::gid_t,
) -> io::Result<Vec<Unsealed>> {
    models::prepare_model_store(run_dir, uid, gid).map_err(io::Error::other)?;
    let mut out = Vec::new();
    for user in users_with(sealed_dir, ".dat")? {
        let plain = plain_path(sealed_dir, &user);
        let result = fs::read(&plain)
            .and_then(|bytes| seal_bytes(tool, sealed_dir, &user, &bytes))
            .and_then(|()| fs::remove_file(&plain));
        if let Err(e) = result {
            out.push(Unsealed {
                user,
                migrated: false,
                result: Err(format!("cannot seal the plaintext model on disk: {e}")),
            });
            continue;
        }
        out.push(Unsealed {
            user,
            migrated: true,
            result: Ok(()),
        });
    }
    for user in users_with(sealed_dir, SUFFIX)? {
        let result = unseal_bytes(tool, sealed_dir, &user)
            .and_then(|bytes| {
                serde_json::from_slice::<Vec<FaceModel>>(&bytes)
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
            })
            .and_then(|items| {
                models::save_user_models_owned(run_dir, &user, &items, uid, gid)
                    .map_err(io::Error::other)
            })
            .map_err(|e| e.to_string());
        match out.iter_mut().find(|u| u.user == user) {
            Some(existing) => existing.result = existing.result.clone().and(result),
            None => out.push(Unsealed {
                user,
                migrated: false,
                result,
            }),
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fake systemd-creds. Written once: writing an executable while another test
    /// forks makes running it fail with ETXTBSY.
    fn fake_tool() -> PathBuf {
        static TOOL: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
        TOOL.get_or_init(|| {
            let dir = std::env::temp_dir().join(format!("peekin-sealed-tool-{}", std::process::id()));
            fs::create_dir_all(&dir).unwrap();
            let tool = dir.join("fake-creds");
            fs::write(
                &tool,
                "#!/bin/sh\n\
                 case \"$1\" in\n\
                 encrypt) { echo \"SEALED $2\"; cat; } > \"$4\" ;;\n\
                 decrypt) read -r tag name < \"$3\"; [ \"$tag $name\" = \"SEALED $2\" ] || exit 1; tail -n +2 \"$3\" ;;\n\
                 esac\n",
            )
            .unwrap();
            fs::set_permissions(&tool, fs::Permissions::from_mode(0o755)).unwrap();
            tool
        })
        .clone()
    }

    fn setup(name: &str) -> (PathBuf, PathBuf, PathBuf, PathBuf) {
        let root =
            std::env::temp_dir().join(format!("peekin-sealed-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        let (sealed, run) = (root.join("etc"), root.join("run"));
        fs::create_dir_all(&sealed).unwrap();
        (root, sealed, run, fake_tool())
    }

    fn me() -> (libc::uid_t, libc::gid_t) {
        unsafe { (libc::geteuid(), libc::getegid()) }
    }

    const MODELS: &str = r#"[{"id":0,"label":"a","time":1,"data":[[1.0]]}]"#;

    #[test]
    fn plaintext_on_disk_is_sealed_moved_to_memory_and_deleted() {
        let (root, sealed, run, tool) = setup("migrate");
        fs::write(sealed.join("alice.dat"), MODELS).unwrap();
        let (uid, gid) = me();
        let report = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert_eq!(report.len(), 1);
        assert!(report[0].migrated && report[0].result.is_ok(), "{report:?}");
        assert!(!sealed.join("alice.dat").exists(), "plaintext left on disk");
        assert!(sealed.join("alice.dat.cred").exists());
        let back = models::load_user_models(&run, "alice").unwrap();
        assert_eq!(back[0].label, "a");
        assert_eq!(
            fs::metadata(run.join("alice.dat"))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o640
        );
        // A second boot just decrypts again.
        fs::remove_dir_all(&run).unwrap();
        let again = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert!(!again[0].migrated && again[0].result.is_ok(), "{again:?}");
        assert!(run.join("alice.dat").exists());
        // A credential that cannot be decrypted is reported, not skipped.
        fs::write(sealed.join("bob.dat.cred"), "garbage\n").unwrap();
        let broken = unseal_all(&tool, &sealed, &run, uid, gid).unwrap();
        assert!(
            broken.iter().any(|u| u.user == "bob" && u.result.is_err()),
            "{broken:?}"
        );
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn persist_seals_changes_and_removes_the_sealed_copy_with_the_last_model() {
        let (root, sealed, run, tool) = setup("persist");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("alice.dat"), MODELS).unwrap();
        persist_with(&tool, &run, &sealed, "alice").unwrap();
        let cred = sealed.join("alice.dat.cred");
        let text = fs::read_to_string(&cred).unwrap();
        assert!(
            text.starts_with("SEALED --name=peekin-model-alice\n"),
            "{text}"
        );
        assert_eq!(
            fs::metadata(&cred).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            unseal_bytes(&tool, &sealed, "alice").unwrap(),
            MODELS.as_bytes()
        );
        // The name binds the credential to its user.
        fs::copy(&cred, sealed.join("bob.dat.cred")).unwrap();
        assert!(unseal_bytes(&tool, &sealed, "bob").is_err());
        fs::remove_file(run.join("alice.dat")).unwrap();
        persist_with(&tool, &run, &sealed, "alice").unwrap();
        assert!(!cred.exists(), "no models left, no sealed copy");
        assert!(persist_with(&tool, &run, &sealed, "../x").is_err());
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn a_failing_tool_leaves_no_partial_file() {
        let (root, sealed, run, _) = setup("failing");
        fs::create_dir_all(&run).unwrap();
        fs::write(run.join("alice.dat"), MODELS).unwrap();
        let err = persist_with(Path::new("/bin/false"), &run, &sealed, "alice").unwrap_err();
        assert!(err.to_string().contains("failed"), "{err}");
        assert_eq!(fs::read_dir(&sealed).unwrap().count(), 0);
        let _ = fs::remove_dir_all(root);
    }
}
